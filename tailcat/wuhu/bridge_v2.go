package main

/*
#include <stdint.h>
typedef int (*wt_allow_peer_fn)(uintptr_t context, const uint8_t peer[32]);
typedef void (*wt_peer_presence_fn)(uintptr_t context, const uint8_t peer[32], int connected);

static inline int wt_call_allow(wt_allow_peer_fn f, uintptr_t ctx, const uint8_t *peer) {
    return f(ctx, peer);
}
static inline void wt_call_presence(wt_peer_presence_fn f, uintptr_t ctx, const uint8_t *peer, int connected) {
    f(ctx, peer, connected);
}
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"unsafe"

	"go4.org/mem"
	"tailscale.com/types/key"
)

func keyBytes(p *C.uint8_t) *[32]byte { return (*[32]byte)(unsafe.Pointer(p)) }

func cAllow(f C.wt_allow_peer_fn, cookie C.uintptr_t) allowPeer {
	return func(k key.NodePublic) bool {
		peer := k.Raw32()
		return C.wt_call_allow(f, cookie, (*C.uint8_t)(unsafe.Pointer(&peer))) != 0
	}
}

//export wt_peer_key
func wt_peer_key(ed, out *C.uint8_t) *C.char {
	return call(func() error {
		if ed == nil || out == nil {
			return errors.New("tailcat: missing public key or output")
		}
		k, err := nodePublicKey(*keyBytes(ed))
		if err == nil {
			*keyBytes(out) = k.Raw32()
		}
		return err
	})
}

//export wt_node_v2
func wt_node_v2(seed *C.uint8_t, region *C.char, allow C.wt_allow_peer_fn, cookie C.uintptr_t, out *C.uintptr_t) *C.char {
	return call(func() error {
		if seed == nil || region == nil || allow == nil || out == nil {
			return errors.New("tailcat: missing node seed, region, callback, or output")
		}
		n, err := newProcessNode(*keyBytes(seed), C.GoString(region), cAllow(allow, cookie))
		if err == nil {
			*out = C.uintptr_t(cgo.NewHandle(n))
		}
		return err
	})
}

//export wt_node_dial
func wt_node_dial(h C.uintptr_t, peer *C.uint8_t, timeoutMS C.int64_t, out *C.int) *C.char {
	return call(func() error {
		if peer == nil || out == nil {
			return errors.New("tailcat: missing peer key or output")
		}
		ctx, cancel, err := streamContext(int64(timeoutMS))
		if err != nil {
			return err
		}
		defer cancel()
		k := key.NodePublicFromRaw32(mem.B(keyBytes(peer)[:]))
		fd, err := cgo.Handle(h).Value().(*nodeV2).dial(ctx, k)
		if err == nil {
			*out = C.int(fd)
		}
		return err
	})
}

//export wt_node_accept
func wt_node_accept(h C.uintptr_t, timeoutMS C.int64_t, out *C.int, peer *C.uint8_t) *C.char {
	return call(func() error {
		if out == nil || peer == nil {
			return errors.New("tailcat: missing accept outputs")
		}
		ctx, cancel, err := streamContext(int64(timeoutMS))
		if err != nil {
			return err
		}
		defer cancel()
		fd, k, err := cgo.Handle(h).Value().(*nodeV2).accept(ctx)
		if err == nil {
			*out = C.int(fd)
			*keyBytes(peer) = k.Raw32()
		}
		return err
	})
}

//export wt_relay
func wt_relay(allow C.wt_allow_peer_fn, presence C.wt_peer_presence_fn, cookie C.uintptr_t, out *C.uintptr_t) *C.char {
	return call(func() error {
		if allow == nil || presence == nil || out == nil {
			return errors.New("tailcat: missing relay callbacks or output")
		}
		r, err := newRelay(cAllow(allow, cookie), func(k key.NodePublic, present bool) {
			peer := k.Raw32()
			var connected C.int
			if present {
				connected = 1
			}
			C.wt_call_presence(presence, cookie, (*C.uint8_t)(unsafe.Pointer(&peer)), connected)
		})
		if err == nil {
			*out = C.uintptr_t(cgo.NewHandle(r))
		}
		return err
	})
}

//export wt_relay_serve
func wt_relay_serve(h C.uintptr_t, fd C.int) *C.char {
	return call(func() error {
		return cgo.Handle(h).Value().(*derpRelay).serveFD(int(fd))
	})
}
