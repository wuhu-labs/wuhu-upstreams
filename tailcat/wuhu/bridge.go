// Command wuhutailcat is the C library Wuhu links (wuhu_tailcat.h): a tailcat node that forwards to one local TCP
// endpoint, and a loopback HTTP CONNECT proxy that reaches one tailcat server. Each handle owns everything it opens.
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"io"
	"runtime/cgo"
	"time"
	"unsafe"
)

func main() {}

func call(fn func() error) (message *C.char) {
	defer func() {
		if r := recover(); r != nil {
			message = C.CString(fmt.Sprint("tailcat: ", r))
		}
	}()
	if err := fn(); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export wt_node
func wt_node(identityPath, regionPath *C.char, out *C.uintptr_t) *C.char {
	return call(func() error {
		n, err := newNode(C.GoString(identityPath), C.GoString(regionPath))
		if err == nil {
			*out = C.uintptr_t(cgo.NewHandle(n))
		}
		return err
	})
}

//export wt_node_forward
func wt_node_forward(h C.uintptr_t, host *C.char, port C.uint16_t, address **C.char) *C.char {
	return call(func() error {
		a, err := cgo.Handle(h).Value().(*node).forward(C.GoString(host), uint16(port))
		if err == nil {
			*address = C.CString(a)
		}
		return err
	})
}

//export wt_node_check
func wt_node_check(h C.uintptr_t, timeoutMS C.int64_t) *C.char {
	return call(func() error {
		return cgo.Handle(h).Value().(*node).check(time.Duration(timeoutMS) * time.Millisecond)
	})
}

//export wt_proxy
func wt_proxy(address, authority, credential *C.char, out *C.uintptr_t, port *C.uint16_t) *C.char {
	return call(func() error {
		p, err := newProxy(C.GoString(address), C.GoString(authority), C.GoString(credential))
		if err == nil {
			*out, *port = C.uintptr_t(cgo.NewHandle(p)), C.uint16_t(p.port)
		}
		return err
	})
}

//export wt_proxy_route
func wt_proxy_route(h C.uintptr_t, timeoutMS C.int64_t, direct *C.int32_t, relay **C.char) *C.char {
	return call(func() error {
		d, r, err := cgo.Handle(h).Value().(*proxy).client.route(time.Duration(timeoutMS) * time.Millisecond)
		*direct, *relay = 0, nil
		if d {
			*direct = 1
		}
		if r != "" {
			*relay = C.CString(r)
		}
		return err
	})
}

//export wt_close
func wt_close(h C.uintptr_t) {
	wt_free(call(func() error {
		handle := cgo.Handle(h)
		closer := handle.Value().(io.Closer)
		handle.Delete()
		return closer.Close()
	}))
}

//export wt_free
func wt_free(message *C.char) {
	C.free(unsafe.Pointer(message))
}
