package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"golang.org/x/sys/unix"
	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestNodeKeyConversion(t *testing.T) {
	for range 16 {
		ed, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		got, err := nodePublicKey([32]byte(ed))
		if want := nodePrivateKey([32]byte(priv.Seed())).Public(); got != want || err != nil {
			t.Fatalf("converted public key = %v, %v; want %v", got, err, want)
		}
	}
	for _, invalid := range [][32]byte{{0}, {1}, {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}} {
		if _, err := nodePublicKey(invalid); err == nil {
			t.Fatalf("converted invalid Ed25519 public key %x", invalid)
		}
	}
}

// TestNodeV2Mesh exercises the same FD seam used by the C ABI, including the
// plaintext socket a TLS-terminating HTTP server hands to the relay.
func TestNodeV2Mesh(t *testing.T) {
	for _, name := range []string{"TS_DEBUG_NEVER_DIRECT_UDP", "IN_TS_TEST"} {
		old := os.Getenv(name)
		envknob.Setenv(name, "true")
		t.Cleanup(func() { envknob.Setenv(name, old) })
	}
	type event struct {
		peer    key.NodePublic
		present bool
	}
	events := make(chan event, 64)
	deniedByRelay := make(chan key.NodePublic, 64)
	deniedByNode := make(chan key.NodePublic, 64)
	var relayOverride, badPresent atomic.Bool
	seeds := make([][32]byte, 4)
	keys := make([]key.NodePublic, len(seeds))
	roster := make(map[key.NodePublic]bool)
	for i := range seeds {
		if _, err := rand.Read(seeds[i][:]); err != nil {
			t.Fatal(err)
		}
		keys[i] = nodePrivateKey(seeds[i]).Public()
		if i < 3 {
			roster[keys[i]] = true
		}
	}
	r, err := newRelay(func(k key.NodePublic) bool {
		if roster[k] || k == keys[3] && relayOverride.Load() {
			return true
		}
		deniedByRelay <- k
		return false
	}, func(k key.NodePublic, present bool) {
		if k == keys[3] && present {
			badPresent.Store(true)
		}
		events <- event{k, present}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	region := testRelayRegion(t, r)

	start := func(i int) *nodeV2 {
		t.Helper()
		n, err := newNodeV2(seeds[i], region, func(k key.NodePublic) bool {
			if roster[k] {
				return true
			}
			deniedByNode <- k
			return false
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		return n
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	nodes := []*nodeV2{start(0), start(1), start(2)}
	gotPresent := make(map[key.NodePublic]bool)
	for len(gotPresent) != len(nodes) {
		select {
		case e := <-events:
			if !roster[e.peer] {
				t.Fatalf("unexpected relay presence: %+v", e)
			}
			if e.present {
				gotPresent[e.peer] = true
			} else {
				delete(gotPresent, e.peer)
			}
		case <-ctx.Done():
			t.Fatal("three nodes did not join the relay:", ctx.Err())
		}
	}

	type pair struct{ src, dst key.NodePublic }
	type stream struct {
		pair
		conn *net.UnixConn
		err  error
	}
	dials, accepts := make(chan stream, 6), make(chan stream, 6)
	for i, n := range nodes {
		for j, remote := range nodes {
			if i == j {
				continue
			}
			src, dst := keys[i], keys[j]
			go func() {
				fd, err := n.dial(ctx, dst)
				c, err := testAdoptStream(t, fd, err)
				dials <- stream{pair{src, dst}, c, err}
			}()
			go func() {
				fd, peer, err := remote.accept(ctx)
				c, err := testAdoptStream(t, fd, err)
				accepts <- stream{pair{peer, dst}, c, err}
			}()
		}
	}
	out, in := make(map[pair]*net.UnixConn), make(map[pair]*net.UnixConn)
	for range 6 {
		for ch, peers := range map[chan stream]map[pair]*net.UnixConn{dials: out, accepts: in} {
			s := <-ch
			if s.err != nil {
				t.Fatal(s.err)
			}
			if peers[s.pair] != nil || s.src == s.dst || !roster[s.src] || !roster[s.dst] {
				t.Fatalf("unexpected peer pair %+v", s.pair)
			}
			peers[s.pair] = s.conn
		}
	}
	// All six streams are open before the first write. Write and half-close
	// both sides, then check payload and EOF independently at each end.
	for p, c := range out {
		other := in[p]
		if other == nil {
			t.Fatalf("no accept for %+v", p)
		}
		for i, sender := range []*net.UnixConn{c, other} {
			sender.SetDeadline(time.Now().Add(5 * time.Second))
			data := fmt.Sprintf("%v → %v, direction %d", p.src, p.dst, i)
			if _, err := io.WriteString(sender, data); err != nil {
				t.Fatal(err)
			}
			if err := sender.CloseWrite(); err != nil {
				t.Fatal(err)
			}
		}
		for i, receiver := range []*net.UnixConn{other, c} {
			want := fmt.Sprintf("%v → %v, direction %d", p.src, p.dst, i)
			if got, err := io.ReadAll(receiver); err != nil || string(got) != want {
				t.Fatalf("stream received %q, %v; want %q and EOF", got, err, want)
			}
		}
	}

	bad := start(3)
	tryDenied := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		defer cancel()
		if fd, err := bad.dial(ctx, keys[0]); err == nil {
			unix.Close(fd)
			t.Fatal("refused node dial succeeded")
		}
	}
	tryDenied()
	select {
	case got := <-deniedByRelay:
		if got != keys[3] {
			t.Fatalf("relay denied %v; want %v", got, keys[3])
		}
	default:
		t.Fatal("no relay admission query for refused node")
	}
	if badPresent.Load() {
		t.Fatal("relay reported presence for a key it denies")
	}
	select {
	case k := <-deniedByNode:
		t.Fatalf("refused relay client reached node admission: %v", k)
	default:
	}

	// Admit the same key to the relay only, so it can reach the node's
	// independent admission check and be refused there as well.
	waitForBad := func(present bool) {
		t.Helper()
		for {
			select {
			case e := <-events:
				if e == (event{keys[3], present}) {
					return
				}
			case <-ctx.Done():
				t.Fatalf("relay did not report presence=%v for fourth node", present)
			}
		}
	}
	relayOverride.Store(true)
	waitForBad(true)
	acceptCtx, stop := context.WithCancel(ctx)
	deniedAccept := make(chan error, 1)
	go func() {
		fd, _, err := nodes[0].accept(acceptCtx)
		if err == nil {
			unix.Close(fd)
		}
		deniedAccept <- err
	}()
	tryDenied()
	stop()
	if err := <-deniedAccept; !errors.Is(err, context.Canceled) {
		t.Fatalf("node accepted refused stream: %v", err)
	}
	select {
	case got := <-deniedByNode:
		if got != keys[3] {
			t.Fatalf("node denied %v; want %v", got, keys[3])
		}
	default:
		t.Fatal("no node admission query for refused node")
	}
	bad.Close()
	waitForBad(false)
}

func testAdoptStream(t *testing.T, fd int, err error) (*net.UnixConn, error) {
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "test tailcat stream")
	defer f.Close()
	if flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		return nil, fmt.Errorf("stream FD lacks CLOEXEC, fcntl = %d, %v", flags, err)
	}
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { c.Close() })
	return c.(*net.UnixConn), nil
}

type upgradedConn struct {
	*tls.Conn
	r io.Reader
}

func (c upgradedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func testRelayRegion(t *testing.T, r *derpRelay) string {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/derp/probe" || req.URL.Path == "/derp/latency-check" {
			derpserver.ProbeHandler(w, req)
			return
		}
		if req.URL.Path != "/derp" || !strings.EqualFold(req.Header.Get("Upgrade"), "DERP") {
			http.NotFound(w, req)
			return
		}
		c, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n")
		if err := rw.Flush(); err != nil {
			return
		}
		fd, pipe, err := streamSocketPair()
		if err != nil {
			t.Error(err)
			return
		}
		defer pipe.Close()
		if err := r.serveFD(fd); err != nil {
			unix.Close(fd)
			if !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
			return
		}
		tailcat.ProxyConns(upgradedConn{c.(*tls.Conn), rw.Reader}, pipe)
	}))
	t.Cleanup(s.Close)
	stun, stopSTUN := stuntest.Serve(t)
	t.Cleanup(stopSTUN)
	const id = 1
	region, err := json.Marshal(tailcfg.DERPRegion{RegionID: id, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
		Name: "test", RegionID: id, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
		DERPPort: s.Listener.Addr().(*net.TCPAddr).Port, STUNPort: stun.Port, STUNTestIP: "127.0.0.1", InsecureForTests: true,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(region)
}
