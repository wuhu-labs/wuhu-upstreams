/* Wuhu's C ABI over iroh 1.x: endpoints, connections, QUIC streams and an embedded relay.
 *
 * Threading: every function may be called from any thread. The library runs one multi-threaded
 * runtime per process, created on first use. Callbacks run on one of its threads (or, for a
 * cancelled operation, possibly on the thread calling wi_cancel) and must not block. When the
 * runtime cannot start (the host refuses it threads, say), an operation ends at once with WI_ERROR,
 * its callback running on the calling thread before the call returns; the next call tries again.
 *
 * Asynchronous operations take a wi_callback and an opaque context and return an operation id
 * (never 0). The callback is called exactly once per operation, with the result; the context is
 * the caller's until then. wi_cancel(id) ends a pending operation with WI_CANCELLED; it is a no-op
 * once the operation has its result, so a cancel racing the end can still see OK (with any
 * handles, which are then the caller's to free).
 *
 * Handles are owned by the caller and released with their wi_*_free. A free never waits and is
 * safe while operations on the handle are pending: those keep what they need and finish normally.
 * Two calls must not use one handle while it is being freed.
 *
 * Keys are 32 bytes: an Ed25519 secret key (seed) or public key. No panic crosses this boundary;
 * a panic inside an operation ends it with WI_ERROR. */
#ifndef WUHU_IROH_H
#define WUHU_IROH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wi_endpoint wi_endpoint;
typedef struct wi_connection wi_connection;
typedef struct wi_send wi_send;
typedef struct wi_recv wi_recv;
typedef struct wi_relay wi_relay;
typedef struct wi_watch wi_watch;

typedef enum wi_status {
  WI_OK = 0,
  /* A read reached the peer's finish. */
  WI_FINISHED = 1,
  /* The peer reset the stream being read; code is its error code. */
  WI_RESET = 2,
  /* The peer stopped the stream being written; code is its error code. */
  WI_STOPPED = 3,
  /* The connection or endpoint is closed; message says why. */
  WI_CLOSED = 4,
  WI_CANCELLED = 5,
  /* message says what failed. */
  WI_ERROR = 6,
} wi_status;

/* Everything in a result is valid only during the callback, except handles, which pass to the
 * callee's ownership. Each operation documents which fields it sets; the rest are zero. */
typedef struct wi_result {
  wi_status status;
  uint64_t code;
  void *handles[2];
  const uint8_t *bytes;
  size_t len;
  const char *message;
} wi_result;

typedef void (*wi_callback)(void *context, const wi_result *result);

void wi_cancel(uint64_t operation);

/* Logs the library's events at or above `filter` (an env-filter directive such as "warn" or
 * "iroh=debug,info") to standard error; only the first call takes effect. */
void wi_log_to_stderr(const char *filter);

/* The Ed25519 public key of `secret_key`. */
void wi_secret_key_public(const uint8_t secret_key[32], uint8_t out_public_key[32]);

/* ---- Endpoint ---------------------------------------------------------------------------- */

/* One relay of an endpoint's relay map: its URL and the token presented to it, as
 * "Authorization: Bearer <auth_token>", on each connection to it; NULL for none. A relay outside
 * the map (a peer's, dialled through wi_endpoint_connect) is never presented any token. */
typedef struct wi_relay_entry {
  const char *url;
  const char *auth_token;
} wi_relay_entry;

/* Binds an endpoint for `secret_key` over the `relay_count` relays of `relays` (at least one,
 * copied before return), accepting and dialling the ALPN `alpn`. No discovery service is used: a
 * peer is addressed by its key, a relay URL and direct addresses. The map's URLs never change.
 * iroh keeps one standing connection, to its home relay, and only probes the others (over HTTPS,
 * in a net report at bind and every 20 to 26 s). A report makes home the relay with the best
 * latency over its last 5 minutes of reports, but keeps the old home unless the new one's latency
 * is below 2/3 of the old one's: two similarly near relays can trade home on a missed probe or on
 * jitter, and a home relay that recovers from an outage is not guaranteed to be home again.
 * iroh redials a failed relay with its backoff, 10 ms doubling to 16 s. A relay whose latest
 * connection failed before it was established (a refused token, a broken upgrade, a failed dial)
 * is passed over as home while the report reached another relay; with only such relays reached,
 * the one home longest ago (or never) is home. A relay's first such failure since it last connected
 * runs a full report at once (no report per failed redial), so a home relay that answers probes
 * but refuses its connection is replaced within that report: on localhost about half a second; a
 * relay that drops packets instead holds the report up to its probe timeout (3 s) and its own
 * (5 s), then a dial to the new home follows. A probe that answers clears nothing; a connection
 * to the relay that is established (the home's, or one a dial through it opened) does. A relay
 * that accepts every connection and then drops it is not covered: it can stay home. With every
 * relay down the home stays and is redialled. Neither QUIC address discovery nor port mapping
 * runs: the direct addresses are the bound interfaces'. With `relay_only` it has no IP transport,
 * so every path goes through a relay. `alpn` may be NULL when `alpn_len` is 0. OK: handles[0] is
 * the wi_endpoint. ERROR: message. */
uint64_t wi_endpoint_bind(const uint8_t secret_key[32], const wi_relay_entry *relays,
                          size_t relay_count, bool relay_only, const uint8_t *alpn,
                          size_t alpn_len, wi_callback callback, void *context);

/* Replaces the token presented to `relay_url`, a relay of the endpoint's map; NULL for none. The
 * next connection to that relay presents it, and a dial to it in flight that presents another is
 * restarted by the next wi_endpoint_network_change; a live connection is not touched. This is the
 * only write of the map. OK when the map holds it. ERROR when the URL is not in the map. CLOSED when the endpoint is closed. */
uint64_t wi_endpoint_set_auth_token(const wi_endpoint *endpoint, const char *relay_url,
                                    const char *auth_token, wi_callback callback, void *context);

void wi_endpoint_key(const wi_endpoint *endpoint, uint8_t out_public_key[32]);

/* Dials `public_key` through `relay_url` (any relay, in the map or not; NULL for none) and the
 * `address_count` direct addresses `addresses` ("ip:port", copied before return), at least one of
 * the two. iroh reaches a relay outside the map through a connection of its own, which it closes
 * after 60 s unused; the endpoint does not report it. A dial naming a relay whose latest
 * connection failed first ends that relay's redial backoff (as wi_endpoint_network_change does),
 * so its packets go out over a fresh connection now. OK: handles[0] is the wi_connection, bytes
 * the verified 32-byte key. ERROR or CLOSED: message. */
uint64_t wi_endpoint_connect(const wi_endpoint *endpoint, const uint8_t public_key[32],
                             const char *relay_url, const char *const *addresses,
                             size_t address_count, wi_callback callback, void *context);

/* The next incoming connection whose handshake completes. OK: handles[0] is the wi_connection,
 * bytes the caller's 32-byte Ed25519 key as the handshake verified it. CLOSED once the endpoint
 * is closed. */
uint64_t wi_endpoint_accept(const wi_endpoint *endpoint, wi_callback callback, void *context);

/* Tells iroh the network may have changed: every relay connection is checked (a short-deadline
 * ping, a redial on silence) and every relay redial backoff ends. A dial an earlier check started
 * on the same interfaces is left alone for its whole budget (10 s, by wall-clock time); a dial is
 * restarted when the interfaces changed, when it is older than its budget, when it presents a
 * token the map no longer holds, or always with `after_suspension`, which the caller passes when
 * the device was just suspended (a short suspension can kill a dial's socket without moving the
 * clock far). OK when iroh has taken it in. */
uint64_t wi_endpoint_network_change(const wi_endpoint *endpoint, bool after_suspension,
                                    wi_callback callback, void *context);

typedef enum wi_relay_kind {
  /* The home relay, the one iroh keeps its standing connection to, and it is connected. */
  WI_RELAY_HOME_CONNECTED = 0,
  /* The home relay, dialing; last_error is this relay's previous failure, empty when it has none. */
  WI_RELAY_HOME_CONNECTING = 1,
  /* The home relay, not connected; last_error says why (never empty). */
  WI_RELAY_HOME_DISCONNECTED = 2,
  /* Not connected; the last net report reached it, in latency_micros. */
  WI_RELAY_REACHABLE = 3,
  /* Not connected; the last net report did not reach it. */
  WI_RELAY_UNREACHABLE = 4,
  /* Not connected; no net report has finished yet. */
  WI_RELAY_UNPROBED = 5,
  /* Not home: its latest connection failed before it was established, so reports pass it over
   * while they reach another relay (see wi_endpoint_bind); still probed, and dialled for peers
   * that name it. last_error is that failure (never empty). A relay holding home while failing is
   * WI_RELAY_HOME_CONNECTING or WI_RELAY_HOME_DISCONNECTED, never this. */
  WI_RELAY_FAILED = 6,
} wi_relay_kind;

/* One relay of the map. url is the whole URL in iroh's form (a trailing slash); last_error is NULL
 * except for WI_RELAY_HOME_CONNECTING (NULL when the relay has not failed), WI_RELAY_HOME_DISCONNECTED
 * and WI_RELAY_FAILED; latency_micros is 0 except for WI_RELAY_REACHABLE. The strings belong to
 * the wi_relays the state came from and live until it is freed. */
typedef struct wi_relay_state {
  const char *url;
  wi_relay_kind kind;
  const char *last_error;
  uint64_t latency_micros;
} wi_relay_state;

typedef struct wi_relays wi_relays;

/* The states of the relays of the map, one per configured relay in URL order, as one read saw
 * them; NULL on failure. No relay is a home kind until the endpoint has picked its home. */
wi_relays *wi_endpoint_relays(const wi_endpoint *endpoint);

size_t wi_relays_count(const wi_relays *relays);

/* The state at `index` (below wi_relays_count); its strings live as long as `relays`. */
wi_relay_state wi_relays_get(const wi_relays *relays, size_t index);

void wi_relays_free(wi_relays *relays);

/* The endpoint's direct addresses as peers may dial them: "ip:port" lines, each ending in '\n',
 * of the addresses iroh holds now (the bound interfaces': no address discovery or port mapping), without
 * loopback, link-local or unspecified IPv4 and without IPv6 outside 2000::/3, sorted. Writes the
 * text and a NUL when it fits in `capacity`; returns its length either way (0: none). */
size_t wi_endpoint_direct_addresses(const wi_endpoint *endpoint, char *out, size_t capacity);

/* A cursor over changes to the endpoint's relays (the home relay's state, a net report, or a
 * relay's connection failing before it was established or being established after one) and to
 * its direct addresses from now on, for wi_watch_next; NULL on failure. Every cursor sees every
 * change; a change may leave what wi_endpoint_relays and wi_endpoint_direct_addresses read as it
 * was. */
wi_watch *wi_endpoint_watch(const wi_endpoint *endpoint);

/* Closes every connection and the endpoint. OK when done. The close runs to its end even when this
 * call is cancelled; a later call waits for the same close. */
uint64_t wi_endpoint_close(const wi_endpoint *endpoint, wi_callback callback, void *context);

void wi_endpoint_free(wi_endpoint *endpoint);

/* ---- Connection -------------------------------------------------------------------------- */

void wi_connection_peer(const wi_connection *connection, uint8_t out_public_key[32]);

/* Opens a bidirectional stream; the peer sees it at the first byte or finish.
 * OK: handles[0] is the wi_send, handles[1] the wi_recv. CLOSED: message. */
uint64_t wi_connection_open(const wi_connection *connection, wi_callback callback, void *context);

/* The next stream the peer opened. OK: handles[0] is the wi_send, handles[1] the wi_recv.
 * CLOSED once the connection is closed: message. */
uint64_t wi_connection_accept(const wi_connection *connection, wi_callback callback,
                              void *context);

typedef struct wi_path {
  /* Through the relay; otherwise a direct UDP path. */
  bool relay;
  uint64_t rtt_micros;
  /* The whole relay URL or the remote IP address and port; the caller frees it with
   * wi_string_free. */
  char *remote;
} wi_path;

/* The path the connection sends on now; false (and `out` untouched) when it has none or is
 * closed. */
bool wi_connection_path(const wi_connection *connection, wi_path *out);

/* Frees a string the library handed over (wi_path.remote); NULL is a no-op. */
void wi_string_free(char *text);

/* A cursor over the connection's path events (a path opened, closed or was selected) from now on,
 * for wi_watch_next; NULL on failure. Every cursor sees every event. */
wi_watch *wi_connection_path_watch(const wi_connection *connection);

/* CLOSED when the connection closes: code is the peer's application close code, or the code of
 * the local close that took effect (the one the peer saw: the first wi_connection_close, or 0 when
 * wi_endpoint_close or anything else closed it first), 0 for any other cause; message the peer's
 * reason or the cause (empty for a local close). */
uint64_t wi_connection_closed(const wi_connection *connection, wi_callback callback,
                              void *context);

void wi_connection_close(const wi_connection *connection, uint64_t code);

/* Drops this handle; the connection closes once nothing holds it (streams and operations
 * included). */
void wi_connection_free(wi_connection *connection);

/* ---- Streams ----------------------------------------------------------------------------- */

/* Writes all `len` bytes (copied before return). OK once QUIC flow control has taken them all.
 * STOPPED: code. RESET when wi_send_reset abandoned the stream first: its code. CLOSED or ERROR:
 * message. One pending write per stream. */
uint64_t wi_send_write(const wi_send *send, const uint8_t *bytes, size_t len,
                       wi_callback callback, void *context);

/* Ends the stream after what was written. OK; CLOSED when it is already finished or reset; ERROR,
 * finishing nothing, while a write is pending: from its call until its outcome is decided and its
 * bytes are in QUIC's buffer, which is handed to its callback just after. */
wi_status wi_send_finish(const wi_send *send);

/* Abandons the stream with `code`, at once; a pending write ends with RESET. */
void wi_send_reset(const wi_send *send, uint64_t code);

/* STOPPED once the peer stops the stream: code. FINISHED once a finished stream's data is all
 * acknowledged. RESET, at once, when wi_send_reset abandoned the stream, before or while it waits:
 * its code. CLOSED when the connection is lost first: message. Any number may be pending; nothing
 * is registered with QUIC until one is, and the registration ends with the stream (finished,
 * stopped or reset) or its connection. */
uint64_t wi_send_stopped(const wi_send *send, wi_callback callback, void *context);

/* Drops the handle; a stream neither finished nor reset is reset with code 0. */
void wi_send_free(wi_send *send);

/* Reads up to `max` bytes, `max` at least 1 (0 is ERROR and reads nothing). OK: bytes and len (at
 * least 1). FINISHED at the peer's finish. RESET: code. CLOSED or ERROR: message. One pending
 * read per stream. */
uint64_t wi_recv_read(const wi_recv *recv, size_t max, wi_callback callback, void *context);

/* Asks the peer to stop sending with `code` once no read is pending (cancel a pending read first). */
void wi_recv_stop(const wi_recv *recv, uint64_t code);

/* Drops the handle; a stream not read to its end is stopped with code 0. */
void wi_recv_free(wi_recv *recv);

/* ---- Relay ------------------------------------------------------------------------------- */

/* Admission for the relay. on_connect runs for each client the relay handshake authenticated and
 * decides whether it is admitted; `auth_token` is the client's bearer token (its Authorization
 * header, else its `token` query parameter), NUL-terminated and valid during the call, or NULL;
 * on_disconnect runs exactly once for each admitted connection when it ends. `connection` is
 * unique per process. Both may run concurrently on runtime threads. release(context) runs once,
 * after the last callback, when the relay is gone. */
typedef struct wi_relay_access {
  void *context;
  bool (*on_connect)(void *context, const uint8_t public_key[32], uint64_t connection,
                     const char *auth_token);
  void (*on_disconnect)(void *context, const uint8_t public_key[32], uint64_t connection);
  void (*release)(void *context);
} wi_relay_access;

/* Serves an iroh relay on `address` ("host:port", port 0 picks one): over plain HTTP when both
 * PEM texts are NULL (for a TLS-terminating proxy in front of it), over HTTPS with that
 * certificate chain and key when both are given. With TLS, iroh also keeps a plain listener on
 * 127.0.0.1 with a port of its own that answers only its captive-portal check, never the relay.
 * The relay owns `access` from this call on, failure included. OK: handles[0] is the wi_relay.
 * ERROR: message. */
uint64_t wi_relay_spawn(const char *address, const char *cert_chain_pem, const char *key_pem,
                        wi_relay_access access, wi_callback callback, void *context);

/* The relay's bound address ("ip:port") into `out`; returns its length, 0 when `capacity` is too
 * small. */
size_t wi_relay_address(const wi_relay *relay, char *out, size_t capacity);

/* Bytes the relay has sent to and received from its clients since it started. */
void wi_relay_traffic(const wi_relay *relay, uint64_t *out_sent, uint64_t *out_received);

/* Disconnects every connection of `public_key`; false when it had none. */
bool wi_relay_disconnect(const wi_relay *relay, const uint8_t public_key[32]);

/* Stops serving and disconnects every client. OK when done. The shutdown runs to its end even when
 * this call is cancelled; a later call waits for the same shutdown. */
uint64_t wi_relay_shutdown(const wi_relay *relay, wi_callback callback, void *context);

/* Drops the handle; a relay not shut down is shut down in the background. */
void wi_relay_free(wi_relay *relay);

/* ---- Watch ------------------------------------------------------------------------------- */

/* OK at the cursor's next change since the last one it reported (or since it was made); CLOSED
 * once its endpoint or connection is closed. One pending call per cursor. */
uint64_t wi_watch_next(const wi_watch *watch, wi_callback callback, void *context);

void wi_watch_free(wi_watch *watch);

#ifdef __cplusplus
}
#endif

#endif
