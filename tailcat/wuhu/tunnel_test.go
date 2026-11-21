package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/logger"
)

const credential = "dXNlcjpwYXNz" // user:pass

func TestIdentityIsCreatedOnceAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls", "tailcat.json")
	a, err := loadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", info.Mode(), err)
	}
	b, err := loadIdentity(path)
	if err != nil || !b.PrivateKey.Equal(a.PrivateKey) || b.PresharedKey != a.PresharedKey {
		t.Fatalf("reload changed identity: %v", err)
	}
	text, _ := json.Marshal(map[string]any{"private_key": a.PrivateKey})
	os.WriteFile(path, text, 0o600)
	if _, err := loadIdentity(path); err == nil {
		t.Fatal("accepted an identity without a preshared key")
	}
	if err := createIdentity(path); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(text) {
		t.Fatal("createIdentity replaced an existing file")
	}
}

func TestNodeRejectsMissingRegion(t *testing.T) {
	dir := t.TempDir()
	region := filepath.Join(dir, "region.json")
	os.WriteFile(region, []byte(`{"RegionID":900}`), 0o600)
	if _, err := newNode(filepath.Join(dir, "id.json"), region); err == nil {
		t.Fatal("accepted a region without nodes")
	}
}

// fakeProxy serves the CONNECT protocol with dial in place of tailcat.
func fakeProxy(t *testing.T, dial dialer) *proxy {
	p := &proxy{authority: "space.test:443", authorization: "Basic " + credential, client: &client{}}
	if err := p.listen(dial); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func exchange(t *testing.T, p *proxy, request string) (status string, conn net.Conn, r *bufio.Reader) {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p.port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	io.WriteString(conn, request)
	r = bufio.NewReader(conn)
	line, _ := r.ReadString('\n')
	for {
		if h, _ := r.ReadString('\n'); h == "\r\n" || h == "" {
			break
		}
	}
	return strings.TrimSpace(line), conn, r
}

func TestProxyAdmitsOnlyItsAuthorityAndCredential(t *testing.T) {
	failing := func() (net.Conn, func(), error) { return nil, nil, errors.New("down") }
	target := echoServer(t)
	echo := func() (net.Conn, func(), error) {
		c, err := net.Dial("tcp", target)
		return c, func() {}, err
	}
	auth := "Proxy-Authorization: Basic " + credential + "\r\n"
	for _, c := range []struct {
		dial          dialer
		request, want string
	}{
		{echo, "garbage\r\n\r\n", "HTTP/1.1 400 Bad Request"},
		{echo, "CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443\r\n" + auth + "\r\n", "HTTP/1.1 403 Forbidden"},
		{echo, "GET http://space.test:443/ HTTP/1.1\r\nHost: space.test\r\n" + auth + "\r\n", "HTTP/1.1 403 Forbidden"},
		{echo, "CONNECT space.test:443 HTTP/1.1\r\nHost: space.test:443\r\n\r\n", "HTTP/1.1 407 Proxy Authentication Required"},
		{echo, "CONNECT space.test:443 HTTP/1.1\r\nHost: space.test:443\r\nProxy-Authorization: Basic eDp5\r\n\r\n", "HTTP/1.1 407 Proxy Authentication Required"},
		{failing, "CONNECT space.test:443 HTTP/1.1\r\nHost: space.test:443\r\n" + auth + "\r\n", "HTTP/1.1 502 Bad Gateway"},
	} {
		if status, _, _ := exchange(t, fakeProxy(t, c.dial), c.request); status != c.want {
			t.Errorf("%q: got %q, want %q", c.request, status, c.want)
		}
	}
	status, conn, r := exchange(t, fakeProxy(t, echo), "CONNECT space.test:443 HTTP/1.1\r\nHost: space.test:443\r\n"+auth+"\r\nearly")
	if status != "HTTP/1.1 200 Connection Established" {
		t.Fatal(status)
	}
	io.WriteString(conn, " bytes")
	conn.(*net.TCPConn).CloseWrite()
	if rest, _ := io.ReadAll(r); string(rest) != "early bytes" {
		t.Fatalf("echoed %q", rest)
	}
}

func TestProxyTimesOutASilentClient(t *testing.T) {
	defer func(d time.Duration) { headTimeout = d }(headTimeout)
	headTimeout = 50 * time.Millisecond
	p := fakeProxy(t, nil)
	if status, _, _ := exchange(t, p, "CONNECT space.test:443"); status != "HTTP/1.1 400 Bad Request" {
		t.Fatal(status)
	}
}

type fakePeer struct {
	fail   bool
	closed chan struct{}
}

func (f *fakePeer) DialTCPPort(context.Context, uint16) (net.Conn, error) {
	if f.fail {
		return nil, errors.New("forgotten")
	}
	a, _ := net.Pipe()
	return a, nil
}
func (f *fakePeer) DiscoPing(context.Context) (*ipnstate.PingResult, error) { return nil, nil }
func (f *fakePeer) Close() error                                            { close(f.closed); return nil }

func TestClientRetiresAFailedPeerAfterItsLeases(t *testing.T) {
	var peers []*fakePeer
	failing := false
	c := &client{open: func() peer {
		p := &fakePeer{fail: failing, closed: make(chan struct{})}
		peers = append(peers, p)
		return p
	}}
	_, release, err := c.dial()
	if err != nil {
		t.Fatal(err)
	}
	peers[0].fail = true
	if _, _, err := c.dial(); err != nil || len(peers) != 2 {
		t.Fatalf("retry on a fresh peer: %v, %d peers", err, len(peers))
	}
	select {
	case <-peers[0].closed:
		t.Fatal("closed a peer with an open stream")
	default:
	}
	release()
	<-peers[0].closed

	peers[1].fail, failing = true, true
	if _, _, err := c.dial(); err == nil || len(peers) != 3 {
		t.Fatalf("two attempts: %v, %d peers", err, len(peers))
	}
	<-peers[2].closed
	if len(c.peers) != 1 {
		t.Fatalf("%d peers kept", len(c.peers))
	}
}

// relay runs a node forwarding to target and a proxy for authority reaching it, against a local DERP relay.
func relay(t *testing.T, target, authority string) (*node, *proxy, func() *node) {
	dm := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	dir := t.TempDir()
	region, _ := json.Marshal(dm.Regions[1])
	os.WriteFile(filepath.Join(dir, "region.json"), region, 0o600)
	host, port, _ := net.SplitHostPort(target)
	var p *proxy
	start := func() *node {
		n, err := newNode(filepath.Join(dir, "id.json"), filepath.Join(dir, "region.json"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		var number uint16
		fmt.Sscan(port, &number)
		address, err := n.forward(host, number)
		if err != nil {
			t.Fatal(err)
		}
		if p == nil {
			if p, err = newProxy(address, authority, credential); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { p.Close() })
		}
		return n
	}
	return start(), p, start
}

func viaProxy(p *proxy, pool *tls.Config) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", p.port), User: url.UserPassword("user", "pass")}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: pool, ForceAttemptHTTP2: true}}
}

func TestPinnedHTTPSAndStreamsThroughTailcat(t *testing.T) {
	defer func(d time.Duration) { dialTimeout = d }(dialTimeout)
	dialTimeout = 2 * time.Second
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: one\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "hello "+r.Host)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	old, p, restart := relay(t, server.Listener.Addr().String(), "example.com:443")

	pinned := viaProxy(p, &tls.Config{RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: "example.com"})
	get := func(c *http.Client) (string, error) {
		resp, err := c.Get("https://example.com/")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	if body, err := get(pinned); err != nil || body != "hello example.com" {
		t.Fatalf("pinned GET: %q, %v", body, err)
	}
	if err := old.check(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := get(viaProxy(p, &tls.Config{ServerName: "example.com"})); err == nil {
		t.Fatal("unpinned client trusted the server")
	}
	resp, err := pinned.Get("https://example.com/events")
	if err != nil {
		t.Fatal(err)
	}
	events := bufio.NewReader(resp.Body)
	if line, _ := events.ReadString('\n'); line != "data: one\n" {
		t.Fatalf("event %q", line)
	}
	if _, err := pinned.Get("https://other.test/"); err == nil {
		t.Fatal("proxy tunneled another authority")
	}

	next := make(chan *node)
	go func() { next <- restart() }()
	select {
	case <-next:
		t.Fatal("a second node joined with the identity held")
	case <-time.After(3 * lockPoll):
	}
	old.Close()
	if _, err := io.ReadAll(events); err == nil {
		t.Fatal("stream outlived its node")
	}
	if err := (<-next).check(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	fresh := viaProxy(p, &tls.Config{RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: "example.com"})
	if body, err := get(fresh); err != nil || body != "hello example.com" {
		t.Fatalf("GET after restart: %q, %v", body, err)
	}
}

func TestHalfCloseAndRouteThroughTailcat(t *testing.T) {
	n, p, _ := relay(t, echoServer(t), "space.test:443")
	body := strings.Repeat("x", 4<<20)
	status, conn, r := exchange(t, p, "CONNECT space.test:443 HTTP/1.1\r\nHost: space.test:443\r\nProxy-Authorization: Basic "+credential+"\r\n\r\n")
	if status != "HTTP/1.1 200 Connection Established" {
		t.Fatal(status)
	}
	go func() { io.WriteString(conn, body); conn.(*net.TCPConn).CloseWrite() }()
	if echoed, err := io.ReadAll(r); err != nil || string(echoed) != body {
		t.Fatalf("echoed %d bytes, %v", len(echoed), err)
	}
	if _, _, err := p.client.route(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	status, conn, _ = exchange(t, p, "CONNECT space.test:443 HTTP/1.1\r\nHost: space.test:443\r\nProxy-Authorization: Basic "+credential+"\r\n\r\n")
	if status != "HTTP/1.1 200 Connection Established" {
		t.Fatal(status)
	}
	p.Close()
	n.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Fatalf("closing the proxy left its stream open: %v", err)
	}
}

// echoServer echoes each connection until its half-close.
func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func isReset(err error) bool { return err != nil && strings.Contains(err.Error(), "reset") }
