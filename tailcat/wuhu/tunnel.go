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
	"syscall"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	servicePort  = 443
	drainTimeout = time.Second
	maxStreams   = 512
)

// Variables so tests can shorten them.
var (
	dialTimeout = 10 * time.Second
	headTimeout = 10 * time.Second
	lockPoll    = 100 * time.Millisecond
)

// streams owns open streams, each an accepted connection and the connection it is spliced to: at most maxStreams, all
// closed by close.
type streams struct {
	mu     sync.Mutex
	closed bool
	open   map[net.Conn]net.Conn
}

// admit takes c as a new stream, or closes it when full or closed.
func (s *streams) admit(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.open) >= maxStreams {
		c.Close()
		return false
	}
	if s.open == nil {
		s.open = map[net.Conn]net.Conn{}
	}
	s.open[c] = nil
	return true
}

// splice runs upstream's ProxyConns between the admitted c and up: each end of stream travels on as a half-close, and
// gVisor's FIN drains before the close.
func (s *streams) splice(c, up net.Conn) {
	s.mu.Lock()
	live := !s.closed
	if live {
		s.open[c] = up
	}
	s.mu.Unlock()
	if live {
		tailcat.ProxyConns(c, up)
	}
	up.Close()
	s.drop(c)
}

func (s *streams) drop(c net.Conn) {
	c.Close()
	s.mu.Lock()
	delete(s.open, c)
	s.mu.Unlock()
}

func (s *streams) close() {
	s.mu.Lock()
	s.closed = true
	open := s.open
	s.open = nil
	s.mu.Unlock()
	for c, up := range open {
		c.Close()
		if up != nil {
			up.Close()
		}
	}
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
	server   *tailcat.Server
	identity *os.File
	streams  streams
	stop     context.CancelFunc
	stopped  context.Context
	mu       sync.Mutex
	started  bool
	ln       net.Listener
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
	file, err := os.Open(identityPath)
	if err != nil {
		return nil, err
	}
	n := &node{server: &tailcat.Server{Key: id.PrivateKey, PresharedKey: id.PresharedKey, Region: &region, Logf: logger.Discard}, identity: file}
	n.stopped, n.stop = context.WithCancel(context.Background())
	return n, nil
}

// Close ends the node's streams and lets their FINs reach the clients before the node leaves tailcat (a client whose
// stream just vanished would wait on it forever), then hands the identity to the next node waiting for it.
func (n *node) Close() error {
	n.stop()
	n.mu.Lock()
	defer n.mu.Unlock()
	n.streams.close()
	if n.ln != nil {
		n.ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		n.server.DrainTCP(ctx)
	}
	err := n.server.Close()
	n.identity.Close()
	return err
}

// forward joins tailcat once no other node holds the identity, and splices each connection a client opens to the
// service port to a fresh connection to host:port. It returns the node's address.
func (n *node) forward(host string, port uint16) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.started || n.stopped.Err() != nil {
		return "", errors.New("tailcat: node is closed or already forwards")
	}
	n.started = true
	if err := n.lock(); err != nil {
		return "", err
	}
	ln, err := n.server.Listen(n.stopped, "tcp", fmt.Sprintf(":%d", servicePort))
	if err != nil {
		return "", err
	}
	n.ln = ln
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if n.streams.admit(c) {
				go func() {
					if up, err := net.DialTimeout("tcp", target, dialTimeout); err == nil {
						n.streams.splice(c, up)
					} else {
						n.streams.drop(c)
					}
				}()
			}
		}
	}()
	return string(n.server.TailcatAddr()), nil
}

// lock waits for the identity file's exclusive lock: two nodes with one key would contend for its relay home.
func (n *node) lock() error {
	for {
		err := syscall.Flock(int(n.identity.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		select {
		case <-n.stopped.Done():
			return net.ErrClosed
		case <-time.After(lockPoll):
		}
	}
}

// check dials the forwarding node's own address the way a client does.
func (n *node) check(timeout time.Duration) error {
	n.mu.Lock()
	forwarding := n.ln != nil
	n.mu.Unlock()
	if !forwarding {
		return errors.New("tailcat: node does not forward")
	}
	c := &tailcat.Client{Server: n.server.TailcatAddr(), Logf: logger.Discard}
	defer c.Close()
	ctx, cancel := context.WithTimeout(n.stopped, timeout)
	defer cancel()
	conn, err := c.DialTCPPort(ctx, servicePort)
	if err == nil {
		conn.Close()
	}
	return err
}

type dialer func() (conn net.Conn, release func(), err error)

type proxy struct {
	authority, authorization string
	client                   *client
	port                     uint16
	streams                  streams
	mu                       sync.Mutex
	closed                   bool
	ln                       net.Listener
}

func newProxy(address, authority, credential string) (*proxy, error) {
	info, err := tailcat.ParseAddr(tailcat.Addr(address))
	if err != nil {
		return nil, err
	}
	p := &proxy{authority: authority, authorization: "Basic " + credential, client: &client{relays: info.Region, open: func() peer {
		return &tailcat.Client{Server: tailcat.Addr(address), Logf: logger.Discard}
	}}}
	return p, p.listen(p.client.dial)
}

func (p *proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	ln := p.ln
	p.mu.Unlock()
	ln.Close()
	p.streams.close()
	p.client.close()
	return nil
}

func (p *proxy) listen(dial dialer) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	p.port, p.ln = uint16(ln.Addr().(*net.TCPAddr).Port), ln
	go p.accept(ln, dial)
	return nil
}

func (p *proxy) accept(ln net.Listener, dial dialer) {
	for {
		c, err := ln.Accept()
		if err == nil {
			if p.streams.admit(c) {
				go p.tunnel(c, dial)
			}
			continue
		}
		ln.Close()
		// iOS reclaims a suspended app's listening sockets; the same port serves again once the app runs.
		time.Sleep(100 * time.Millisecond)
		p.mu.Lock()
		if !p.closed {
			if ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p.port)))); err == nil {
				p.ln = ln
			}
		}
		closed := p.closed
		p.mu.Unlock()
		if closed || err != nil {
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
		p.streams.drop(c)
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
		p.streams.drop(c)
		return
	}
	p.streams.splice(c, up)
}

type peer interface {
	DialTCPPort(ctx context.Context, port uint16) (net.Conn, error)
	DiscoPing(ctx context.Context) (*ipnstate.PingResult, error)
	Close() error
}

// client reaches one tailcat server through a peer. A restarted server forgets the peers registered with it, so a
// failed dial retires its peer and is tried once more on a fresh one; a retired peer closes when its last lease ends.
type client struct {
	open    func() peer
	relays  []*tailcfg.DERPRegion
	mu      sync.Mutex
	closed  bool
	current *entry
	peers   map[*entry]struct{}
}

type entry struct {
	peer
	leases int
}

func (c *client) lease() (*entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.current == nil {
		c.current = &entry{peer: c.open()}
		if c.peers == nil {
			c.peers = map[*entry]struct{}{}
		}
		c.peers[c.current] = struct{}{}
	}
	c.current.leases++
	return c.current, nil
}

func (c *client) release(e *entry, failed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.leases--
	if failed && c.current == e {
		c.current = nil
	}
	if c.current != e && e.leases == 0 && !c.closed {
		delete(c.peers, e)
		go e.Close()
	}
}

func (c *client) dial() (net.Conn, func(), error) {
	var err error
	for range 2 {
		e, leaseErr := c.lease()
		if leaseErr != nil {
			return nil, nil, leaseErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		var conn net.Conn
		conn, err = e.DialTCPPort(ctx, servicePort)
		cancel()
		if err == nil {
			return conn, sync.OnceFunc(func() { c.release(e, false) }), nil
		}
		c.release(e, true)
	}
	return nil, nil, err
}

func (c *client) close() {
	c.mu.Lock()
	c.closed = true
	peers := c.peers
	c.current, c.peers = nil, nil
	c.mu.Unlock()
	for e := range peers {
		e.Close()
	}
}

// route pings the server: direct, or relayed through the relay host the address names for the path, when it names
// exactly one.
func (c *client) route(timeout time.Duration) (direct bool, relay string, err error) {
	e, err := c.lease()
	if err != nil {
		return false, "", err
	}
	defer c.release(e, false)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r, err := e.DiscoPing(ctx)
	if err != nil || r.Endpoint != "" {
		return err == nil, "", err
	}
	for _, region := range c.relays {
		if (region.RegionID == r.DERPRegionID || len(c.relays) == 1) && len(region.Nodes) == 1 {
			relay = region.Nodes[0].HostName
		}
	}
	return false, relay, nil
}
