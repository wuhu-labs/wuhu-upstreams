package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"filippo.io/edwards25519"
	"github.com/tailscale/tailcat"
	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type allowPeer func(key.NodePublic) bool

func nodePrivateKey(seed [32]byte) key.NodePrivate {
	h := sha512.Sum512(seed[:])
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	return key.NodePrivateFromRaw32(mem.B(h[:32]))
}

// minusOne is -1 modulo the prime order of the Ed25519 subgroup.
var minusOne = sync.OnceValue(func() *edwards25519.Scalar {
	oneBytes := [32]byte{1}
	one, _ := edwards25519.NewScalar().SetCanonicalBytes(oneBytes[:])
	return edwards25519.NewScalar().Negate(one)
})

func nodePublicKey(ed [32]byte) (key.NodePublic, error) {
	p, err := new(edwards25519.Point).SetBytes(ed[:])
	identity := edwards25519.NewIdentityPoint()
	if err != nil || !bytes.Equal(p.Bytes(), ed[:]) || p.Equal(identity) == 1 {
		return key.NodePublic{}, errors.New("tailcat: invalid Ed25519 public key")
	}
	// (order-1)*P + P is zero only for points in the prime-order subgroup.
	q := new(edwards25519.Point).ScalarMult(minusOne(), p)
	if q.Add(q, p).Equal(identity) == 0 {
		return key.NodePublic{}, errors.New("tailcat: invalid Ed25519 public key subgroup")
	}
	return key.NodePublicFromRaw32(mem.B(p.BytesMontgomery())), nil
}

// Only the C ABI leases the process slot. The transport itself can host several
// independent nodes, so integration tests can drive them in one process.
var processNode atomic.Bool

func newProcessNode(seed [32]byte, regionJSON string, allow allowPeer) (*nodeV2, error) {
	if !processNode.CompareAndSwap(false, true) {
		return nil, errors.New("tailcat: a v2 node is already running")
	}
	var started bool
	release := func() { processNode.Store(false) }
	defer func() {
		if !started {
			release()
		}
	}()
	n, err := newNodeV2(seed, regionJSON, allow)
	if err != nil {
		return nil, err
	}
	n.release = release
	started = true
	return n, nil
}

type nodeV2 struct {
	server    *tailcat.Server
	ln        tailcat.ContextListener
	streams   streams
	closeOnce sync.Once
	release   func()

	mu    sync.Mutex
	allow allowPeer
	calls sync.WaitGroup
}

func newNodeV2(seed [32]byte, regionJSON string, allow allowPeer) (*nodeV2, error) {
	var region tailcfg.DERPRegion
	if allow == nil || json.Unmarshal([]byte(regionJSON), &region) != nil || region.RegionID <= 0 || len(region.Nodes) == 0 {
		return nil, errors.New("tailcat: an admission callback and DERP region are required")
	}
	for _, dn := range region.Nodes {
		if dn == nil || dn.RegionID != region.RegionID || dn.HostName == "" {
			return nil, errors.New("tailcat: invalid DERP node in region")
		}
	}
	n := &nodeV2{allow: allow}
	n.server = &tailcat.Server{
		Key:                 nodePrivateKey(seed),
		DisablePresharedKey: true,
		Region:              &region,
		Logf:                logger.Discard,
		AllowClient:         n.admit,
	}
	ln, err := n.server.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", servicePort))
	if err != nil {
		n.Close()
		return nil, err
	}
	n.ln = ln.(tailcat.ContextListener)
	return n, nil
}

func (n *nodeV2) admit(peer key.NodePublic) bool {
	n.mu.Lock()
	allow := n.allow
	if allow != nil {
		n.calls.Add(1)
	}
	n.mu.Unlock()
	if allow == nil {
		return false
	}
	defer n.calls.Done()
	return allow(peer)
}

func (n *nodeV2) Close() error {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		n.allow = nil
		n.mu.Unlock()
		if n.ln != nil {
			n.ln.Close()
		}
		n.streams.close()
		if n.ln != nil {
			// Keep WireGuard and DERP alive while the closed streams' FINs
			// reach their peers. Bound the drain if a peer is gone.
			ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
			n.server.DrainTCP(ctx)
			cancel()
		}
		n.server.Close()
		n.calls.Wait()
		if n.release != nil {
			n.release()
		}
	})
	return nil
}

func (n *nodeV2) dial(ctx context.Context, peer key.NodePublic) (int, error) {
	c, err := n.server.Dial(ctx, peer, servicePort)
	if err != nil {
		return -1, err
	}
	return n.streamFD(c)
}

func (n *nodeV2) accept(ctx context.Context) (int, key.NodePublic, error) {
	c, err := n.ln.AcceptContext(ctx)
	if err != nil {
		return -1, key.NodePublic{}, err
	}
	peer, ok := n.server.PeerKey(c.RemoteAddr())
	if !ok {
		c.Close()
		return -1, key.NodePublic{}, errors.New("tailcat: accepted stream has no peer key")
	}
	fd, err := n.streamFD(c)
	return fd, peer, err
}

func (n *nodeV2) streamFD(c net.Conn) (int, error) {
	if !n.streams.admit(c) {
		return -1, errors.New("tailcat: node is closed or stream limit reached")
	}
	fd, up, err := streamSocketPair()
	if err != nil {
		n.streams.drop(c)
		return -1, err
	}
	go n.streams.splice(c, up)
	return fd, nil
}

func streamSocketPair() (fd int, peer net.Conn, err error) {
	// Darwin does not support SOCK_CLOEXEC on socketpair.
	syscall.ForkLock.RLock()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(pair[0])
		unix.CloseOnExec(pair[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, nil, err
	}
	f := os.NewFile(uintptr(pair[0]), "tailcat stream")
	peer, err = net.FileConn(f)
	f.Close()
	if err != nil {
		unix.Close(pair[1])
		return -1, nil, err
	}
	return pair[1], peer, nil
}

func streamContext(ms int64) (context.Context, context.CancelFunc, error) {
	if ms < 0 || ms > int64((1<<63-1)/time.Millisecond) {
		return nil, nil, errors.New("tailcat: invalid timeout")
	}
	if ms == 0 {
		return context.Background(), func() {}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ms)*time.Millisecond)
	return ctx, cancel, nil
}
