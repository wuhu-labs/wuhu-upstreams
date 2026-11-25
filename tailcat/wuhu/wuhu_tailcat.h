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
// Closes a node, proxy, or relay and its resources. Wakes blocked V2 calls and waits for callbacks to finish.
void wt_close(uintptr_t handle);
void wt_free(char *message);

// V2 uses raw 32-byte X25519 peer IDs. Convert an enrolled Ed25519 public key once with wt_peer_key.
char *wt_peer_key(const uint8_t ed25519[32], uint8_t peer[32]);
// Callbacks may run concurrently on Go threads. Return nonzero to admit. The key is valid only for the call.
// Keep callbacks short; do not call back into this ABI from them. Their context is valid until wt_close returns.
typedef int (*wt_allow_peer_fn)(uintptr_t context, const uint8_t peer[32]);
typedef void (*wt_peer_presence_fn)(uintptr_t context, const uint8_t peer[32], int connected);
// Starts the process's v2 node with a 32-byte Ed25519 seed and a DERPRegion JSON object. No files or PSK.
char *wt_node_v2(const uint8_t seed[32], const char *region_json, wt_allow_peer_fn allow, uintptr_t context,
                 uintptr_t *node);
// Dial/accept streams on the configured relay (Tailcat port 443). A zero timeout adds no caller deadline.
// Success hands the caller a CLOEXEC stream FD to close; wt_close shuts down its bridge end, not the caller's FD.
char *wt_node_dial(uintptr_t node, const uint8_t peer[32], int64_t timeout_ms, int *fd);
char *wt_node_accept(uintptr_t node, int64_t timeout_ms, int *fd, uint8_t peer[32]);
// Starts a relay. Presence reports whether at least one connection for a key is registered (1/0).
char *wt_relay(wt_allow_peer_fn allow, wt_peer_presence_fn presence, uintptr_t context, uintptr_t *relay);
// After the HTTP upgrade, hand over a connected, plaintext stream starting at the first DERP byte (including any
// upgrade lookahead). Success consumes fd and serves it asynchronously; on error the caller still owns fd.
char *wt_relay_serve(uintptr_t relay, int fd);
