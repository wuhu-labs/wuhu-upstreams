package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	servicePort  = 443
	startTimeout = 30 * time.Second
	drainTimeout = time.Second
	maxOpen      = 512
)

// Variables so tests can shorten them.
var (
	dialTimeout = 10 * time.Second
	headTimeout = 10 * time.Second
)

// owner closes everything registered with it, at most maxOpen things at once, and refuses registrations once closed.
type owner struct {
	mu     sync.Mutex
	closed bool
	open   map[io.Closer]struct{}
}

func (o *owner) add(c io.Closer) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || len(o.open) >= maxOpen {
		c.Close()
		return false
	}
	if o.open == nil {
		o.open = map[io.Closer]struct{}{}
	}
	o.open[c] = struct{}{}
	return true
}

func (o *owner) remove(c io.Closer) {
	o.mu.Lock()
	delete(o.open, c)
	o.mu.Unlock()
}

func (o *owner) Close() error {
	o.mu.Lock()
	o.closed = true
	open := o.open
	o.open = nil
	o.mu.Unlock()
	for c := range open {
		c.Close()
	}
	return nil
}

// splice runs upstream's ProxyConns: each end of stream travels on as a half-close, and gVisor's FIN drains before
// the close.
func (o *owner) splice(a, b net.Conn) {
	if o.add(a) && o.add(b) {
		tailcat.ProxyConns(a, b)
	}
	a.Close()
	b.Close()
	o.remove(a)
	o.remove(b)
}

type identity struct {
	PrivateKey   key.NodePrivate      `json:"private_key"`
	PresharedKey tailcat.PresharedKey `json:"preshared_key"`
}

// loadIdentity reads the identity at path, creating it when there is none: the file appears whole, through a hard
// link that never replaces one created meanwhile.
func loadIdentity(path string) (id identity, err error) {
	text, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		err = createIdentity(path)
		if err == nil {
			text, err = os.ReadFile(path)
		}
	}
	if err != nil {
		return id, err
	}
	if json.Unmarshal(text, &id) != nil || id.PrivateKey.IsZero() || id.PresharedKey.IsZero() {
		return id, fmt.Errorf("%s holds no tailcat private_key and preshared_key", path)
	}
	return id, nil
}

func createIdentity(path string) error {
	text, err := json.Marshal(identity{PrivateKey: key.NewNode(), PresharedKey: tailcat.NewPresharedKey()})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".tailcat-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(text)
	if err = errors.Join(err, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

type node struct {
	owner
	server   *tailcat.Server
	stop     context.CancelFunc
	stopped  context.Context
	starting sync.Mutex
	started  bool
}

func newNode(identityPath, regionPath string) (*node, error) {
	id, err := loadIdentity(identityPath)
	if err != nil {
		return nil, err
	}
	text, err := os.ReadFile(regionPath)
	if err != nil {
		return nil, err
	}
	var region tailcfg.DERPRegion
	if json.Unmarshal(text, &region) != nil || region.RegionID == 0 || len(region.Nodes) == 0 {
		return nil, fmt.Errorf("%s holds no DERP region", regionPath)
	}
	n := &node{server: &tailcat.Server{Key: id.PrivateKey, PresharedKey: id.PresharedKey, Region: &region, Logf: logger.Discard}}
	n.stopped, n.stop = context.WithCancel(context.Background())
	return n, nil
}

// Close ends the node's connections and lets their FINs reach the clients before the node leaves tailcat; a client
// whose stream just vanished would wait on it forever.
func (n *node) Close() error {
	n.stop()
	n.starting.Lock()
	defer n.starting.Unlock()
	n.owner.Close()
	if n.started {
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		n.server.DrainTCP(ctx)
	}
	return n.server.Close()
}

// forward joins tailcat and splices each connection a client opens to the service port to a fresh connection to
// host:port. It returns the node's address.
func (n *node) forward(host string, port uint16) (string, error) {
	n.starting.Lock()
	defer n.starting.Unlock()
	if n.started || n.stopped.Err() != nil {
		return "", errors.New("tailcat: node is closed or already forwards")
	}
	ctx, cancel := context.WithTimeout(n.stopped, startTimeout)
	defer cancel()
	ln, err := n.server.Listen(ctx, "tcp", fmt.Sprintf(":%d", servicePort))
	if err != nil {
		return "", err
	}
	if !n.add(ln) {
		return "", net.ErrClosed
	}
	n.started = true
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !n.add(c) {
				continue
			}
			go func() {
				local, err := net.DialTimeout("tcp", target, dialTimeout)
				if err != nil {
					c.Close()
					n.remove(c)
					return
				}
				n.splice(c, local)
			}()
		}
	}()
	return string(n.server.TailcatAddr()), nil
}

type dialer func() (conn net.Conn, release func(), err error)

type proxy struct {
	owner
	authority, authorization string
	client                   *client
	port                     uint16
}

func newProxy(address, authority, credential string) (*proxy, error) {
	if _, err := tailcat.ParseAddr(tailcat.Addr(address)); err != nil {
		return nil, err
	}
	p := &proxy{authority: authority, authorization: "Basic " + credential}
	p.client = &client{owner: &p.owner, open: func() peer { return &tailcat.Client{Server: tailcat.Addr(address), Logf: logger.Discard} }}
	return p, p.listen(p.client.dial)
}

func (p *proxy) listen(dial dialer) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	p.port = uint16(ln.Addr().(*net.TCPAddr).Port)
	if !p.add(ln) {
		return net.ErrClosed
	}
	go p.accept(ln, dial)
	return nil
}

func (p *proxy) accept(ln net.Listener, dial dialer) {
	for {
		c, err := ln.Accept()
		if err == nil {
			if p.add(c) {
				go p.tunnel(c, dial)
			}
			continue
		}
		p.remove(ln)
		ln.Close()
		// iOS reclaims a suspended app's listening sockets; the same port serves again once the app runs.
		time.Sleep(100 * time.Millisecond)
		if ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p.port)))); err != nil || !p.add(ln) {
			return
		}
	}
}

func (p *proxy) tunnel(c net.Conn, dial dialer) {
	c.SetReadDeadline(time.Now().Add(headTimeout))
	head := bufio.NewReader(io.LimitReader(c, 8<<10))
	req, err := http.ReadRequest(head)
	status := ""
	switch {
	case err != nil:
		status = "400 Bad Request"
	case req.Method != http.MethodConnect || req.RequestURI != p.authority:
		status = "403 Forbidden"
	case subtle.ConstantTimeCompare([]byte(req.Header.Get("Proxy-Authorization")), []byte(p.authorization)) != 1:
		status = "407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"wuhu\""
	}
	var up net.Conn
	if status == "" {
		var release func()
		if up, release, err = dial(); err != nil {
			status = "502 Bad Gateway"
		} else {
			defer release()
		}
	}
	if status != "" {
		fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status)
		c.Close()
		p.remove(c)
		return
	}
	c.SetReadDeadline(time.Time{})
	_, err = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if n := head.Buffered(); err == nil && n > 0 {
		leftover, _ := head.Peek(n)
		_, err = up.Write(leftover)
	}
	if err != nil {
		up.Close()
		c.Close()
		p.remove(c)
		return
	}
	p.splice(c, up)
}

type peer interface {
	DialTCPPort(ctx context.Context, port uint16) (net.Conn, error)
	DiscoPing(ctx context.Context) (*ipnstate.PingResult, error)
	Close() error
}

// client reaches one tailcat server through a peer. A restarted server forgets the peers that registered with it, so a
// failed dial on a peer that dialed before replaces the peer and is retried once. The replaced peer carries its open
// streams until they end or the next replacement.
type client struct {
	owner            *owner
	open             func() peer
	mu               sync.Mutex
	current, retired *entry
}

type entry struct {
	peer
	streams   int
	succeeded bool
}

func (c *client) get() (*entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil {
		e := &entry{peer: c.open()}
		if !c.owner.add(e.peer) {
			return nil, net.ErrClosed
		}
		c.current = e
	}
	return c.current, nil
}

func (c *client) dial() (net.Conn, func(), error) {
	for attempt := 0; ; attempt++ {
		e, err := c.get()
		if err != nil {
			return nil, nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		conn, err := e.DialTCPPort(ctx, servicePort)
		cancel()
		c.mu.Lock()
		if err == nil {
			e.succeeded = true
			e.streams++
			c.mu.Unlock()
			return conn, sync.OnceFunc(func() { c.release(e) }), nil
		}
		if c.current == e && e.succeeded {
			c.retire(e)
		}
		retry := attempt == 0 && c.current != e
		c.mu.Unlock()
		if !retry {
			return nil, nil, err
		}
	}
}

// retire takes e out of service and closes the peer retired before it; c.mu is held.
func (c *client) retire(e *entry) {
	if c.retired != nil {
		c.close(c.retired)
	}
	c.current, c.retired = nil, e
	if e.streams == 0 {
		c.close(e)
	}
}

func (c *client) release(e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.streams--
	if e == c.retired && e.streams == 0 {
		c.close(e)
	}
}

func (c *client) close(e *entry) {
	if c.retired == e {
		c.retired = nil
	}
	c.owner.remove(e.peer)
	go e.Close()
}

func (c *client) direct(timeout time.Duration) (bool, error) {
	e, err := c.get()
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r, err := e.DiscoPing(ctx)
	if err != nil {
		return false, err
	}
	return r.Endpoint != "", nil
}
