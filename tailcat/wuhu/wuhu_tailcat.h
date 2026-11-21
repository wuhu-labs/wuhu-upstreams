// The C ABI of Wuhu's tailcat bridge (tailcat/wuhu in github.com/wuhu-labs/wuhu-upstreams). A call that can fail
// returns NULL, or an error message the caller frees with wt_free. A handle stays valid until wt_close.
#include <stdint.h>

// Loads the identity at identity_path, creating it (0600) when absent, and the DERP region JSON at region_path. No
// network yet.
char *wt_node(const char *identity_path, const char *region_path, uintptr_t *node);
// Joins tailcat once no other node holds the identity (waiting until wt_close otherwise) and splices each connection a
// client opens to a fresh TCP connection to host:port; returns the node's address.
char *wt_node_forward(uintptr_t node, const char *host, uint16_t port, char **address);
// Dials the forwarding node's own address through the relay, as a client would.
char *wt_node_check(uintptr_t node, int64_t timeout_ms);
// A loopback HTTP CONNECT proxy that tunnels only `CONNECT <authority>` with `Proxy-Authorization: Basic
// <credential>` to the tailcat server at address.
char *wt_proxy(const char *address, const char *authority, const char *credential, uintptr_t *proxy, uint16_t *port);
// Pings the proxy's server: *direct is 1 over a direct path, 0 through the relay; *relay, when not NULL, names the relay
// host the address gives for that path (free it with wt_free).
char *wt_proxy_route(uintptr_t proxy, int64_t timeout_ms, int32_t *direct, char **relay);
// Closes a node or proxy with every listener, peer and connection it opened.
void wt_close(uintptr_t handle);
void wt_free(char *message);
