package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/types/key"
)

// TestCABI gives the C smoke test a live node and relay. It dials us
// and then accepts a stream from us, through the real archived ABI.
func TestCABI(t *testing.T) {
	smoke := os.Getenv("TAILCAT_ABI_SMOKE")
	if smoke == "" {
		t.Skip("requires the C smoke binary from build.sh")
	}
	for _, name := range []string{"TS_DEBUG_NEVER_DIRECT_UDP", "IN_TS_TEST"} {
		old := os.Getenv(name)
		envknob.Setenv(name, "true")
		t.Cleanup(func() { envknob.Setenv(name, old) })
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var cSeed [32]byte
	if _, err := rand.Read(cSeed[:]); err != nil {
		t.Fatal(err)
	}
	cPeer := nodePrivateKey(cSeed).Public()
	allowAll := func(key.NodePublic) bool { return true }
	r, err := newRelay(allowAll, func(key.NodePublic, bool) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	region := testRelayRegion(t, r)
	n, err := newNodeV2([32]byte(priv.Seed()), region, func(k key.NodePublic) bool { return k == cPeer })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, smoke, region, hex.EncodeToString(cSeed[:]), hex.EncodeToString(pub))
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		if t.Failed() && log.Len() != 0 {
			t.Log(log.String())
		}
	}()
	fd, peer, err := n.accept(ctx)
	in, err := testAdoptStream(t, fd, err)
	if err != nil || peer != cPeer {
		t.Fatalf("accept C peer %v: %v; want %v", peer, err, cPeer)
	}
	in.SetDeadline(time.Now().Add(5 * time.Second))
	var b [1]byte
	if _, err := io.ReadFull(in, b[:]); err != nil || b[0] != 'D' {
		t.Fatalf("C dial sent %q, %v; want D", b, err)
	}
	if _, err := io.WriteString(in, "d"); err != nil {
		t.Fatal(err)
	}
	in.Close()

	fd, err = n.dial(ctx, cPeer)
	out, err := testAdoptStream(t, fd, err)
	if err != nil {
		t.Fatal(err)
	}
	out.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(out, "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(out, b[:]); err != nil || b[0] != 'a' {
		t.Fatalf("C accept sent %q, %v; want a", b, err)
	}
	out.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}
