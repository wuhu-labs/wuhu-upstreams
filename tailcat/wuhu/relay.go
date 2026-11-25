package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type peerPresence func(key.NodePublic, bool)

type derpRelay struct {
	server   *derpserver.Server
	verifier *http.Server
	watch    net.Conn
	ctx      context.Context
	cancel   context.CancelFunc

	mu        sync.Mutex // gates new accepts and callbacks against Close
	closed    bool
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newRelay(allow allowPeer, presence peerPresence) (*derpRelay, error) {
	if allow == nil || presence == nil {
		return nil, errors.New("tailcat: relay requires admission and presence callbacks")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &derpRelay{server: derpserver.New(key.NewNode(), logger.Discard), conns: make(map[net.Conn]struct{})}
	r.ctx, r.cancel = context.WithCancel(context.Background())

	// DERP's public verifier API is HTTP only. Keep it on loopback with an
	// unguessable path so other local processes can't invoke the callback.
	path := "/" + rand.Text()
	r.verifier = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPost || subtle.ConstantTimeCompare([]byte(req.URL.Path), []byte(path)) != 1 {
				http.NotFound(w, req)
				return
			}
			var request tailcfg.DERPAdmitClientRequest
			if json.NewDecoder(http.MaxBytesReader(w, req.Body, 1024)).Decode(&request) != nil || request.NodePublic.IsZero() {
				http.Error(w, "invalid DERP admission request", http.StatusBadRequest)
				return
			}
			r.mu.Lock()
			if r.closed {
				r.mu.Unlock()
				http.Error(w, "relay closed", http.StatusServiceUnavailable)
				return
			}
			r.wg.Add(1)
			r.mu.Unlock()
			defer r.wg.Done()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: allow(request.NodePublic)})
		}),
	}
	r.server.SetVerifyClientURL("http://" + ln.Addr().String() + path)
	r.server.SetVerifyClientURLFailOpen(false)
	// The mesh credential is ephemeral and used only on this in-memory
	// connection. External clients still pass through the verifier.
	var mesh [32]byte
	if _, err := rand.Read(mesh[:]); err != nil {
		ln.Close()
		r.Close()
		return nil, err
	}
	if err := r.server.SetMeshKey(hex.EncodeToString(mesh[:])); err != nil {
		ln.Close()
		r.Close()
		return nil, err
	}
	r.wg.Go(func() { r.verifier.Serve(ln) })
	if err := r.startWatcher(presence); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func relayBuffers(c net.Conn) *bufio.ReadWriter {
	return bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
}

func (r *derpRelay) startWatcher(presence peerPresence) error {
	clientConn, serverConn := net.Pipe()
	r.watch = clientConn
	r.startConn(serverConn)
	startup := time.AfterFunc(10*time.Second, func() { clientConn.Close() })
	defer startup.Stop()
	client, err := derp.NewClient(key.NewNode(), clientConn, relayBuffers(clientConn), logger.Discard, derp.MeshKey(r.server.MeshKey()))
	if err != nil {
		return err
	}
	// Read ServerInfo before issuing Watch on the unbuffered pipe.
	if _, err := client.Recv(); err != nil {
		return err
	}
	if err := client.WatchConnectionChanges(); err != nil {
		return err
	}
	// Before we hand out the relay, wait for the watcher's own entry in
	// the initial snapshot. A short-lived client can't come and go before
	// DERP has registered the watcher.
	for {
		msg, err := client.Recv()
		if err != nil {
			return err
		}
		if m, ok := msg.(derp.PeerPresentMessage); ok && m.Key == client.PublicKey() {
			break
		}
	}
	r.wg.Go(func() {
		present := make(map[key.NodePublic]bool)
		defer func() {
			for k := range present {
				presence(k, false)
			}
		}()
		for {
			msg, err := client.Recv()
			if err != nil {
				// We can no longer report presence; stop the relay rather than
				// continuing to accept unobserved connections.
				if r.ctx.Err() == nil {
					go r.Close()
				}
				return
			}
			switch m := msg.(type) {
			case derp.PeerPresentMessage:
				if m.Key != client.PublicKey() && !present[m.Key] {
					present[m.Key] = true
					presence(m.Key, true)
				}
			case derp.PeerGoneMessage:
				if m.Reason == derp.PeerGoneReasonDisconnected && present[m.Peer] {
					delete(present, m.Peer)
					presence(m.Peer, false)
				}
			}
		}
	})
	return nil
}

// startConn takes ownership of c if the relay is open. The relay keeps
// track of connections even before derpserver.Accept starts running.
func (r *derpRelay) startConn(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[c] = struct{}{}
	r.wg.Go(func() {
		// DERP can pool its writer for mostly idle connections.
		r.server.Accept(r.ctx, c, &bufio.ReadWriter{Reader: bufio.NewReader(c)}, c.RemoteAddr().String())
		r.mu.Lock()
		delete(r.conns, c)
		r.mu.Unlock()
	})
	return true
}

// serveFD takes ownership of fd only on success. net.FileConn gives the
// relay a runtime-pollable connection independent of the caller's FD.
func (r *derpRelay) serveFD(fd int) error {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), "tailcat relay stream")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return err
	}
	switch c.(type) {
	case *net.TCPConn, *net.UnixConn:
	default:
		c.Close()
		return errors.New("tailcat: relay requires a stream socket")
	}
	if remote := c.RemoteAddr(); remote == nil || (remote.Network() != "tcp" && remote.Network() != "unix") {
		c.Close()
		return errors.New("tailcat: relay requires a connected stream socket")
	}
	if !r.startConn(c) {
		c.Close()
		return net.ErrClosed
	}
	unix.Close(fd)
	return nil
}

func (r *derpRelay) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		for c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
		r.verifier.Close()
		if r.watch != nil {
			r.watch.Close()
		}
		r.server.Close()
		r.wg.Wait()
	})
	return nil
}
