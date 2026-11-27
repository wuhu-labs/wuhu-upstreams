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

/* Binds an endpoint for `secret_key` whose only relay is `relay_url`, accepting and dialling the
 * ALPN `alpn`. No discovery service is used: a peer is addressed by (relay URL, key). With
 * `relay_only` it has no IP transport, so every path goes through the relay. `alpn` may be NULL
 * when `alpn_len` is 0. OK: handles[0] is the wi_endpoint. ERROR: message. */
uint64_t wi_endpoint_bind(const uint8_t secret_key[32], const char *relay_url, bool relay_only,
                          const uint8_t *alpn, size_t alpn_len, wi_callback callback,
                          void *context);

void wi_endpoint_key(const wi_endpoint *endpoint, uint8_t out_public_key[32]);

/* Dials `public_key` through the endpoint's own relay, the only relay URL this library ever hands
 * iroh. OK: handles[0] is the wi_connection, bytes the verified 32-byte key. ERROR or CLOSED:
 * message. */
uint64_t wi_endpoint_connect(const wi_endpoint *endpoint, const uint8_t public_key[32],
                             wi_callback callback, void *context);

/* The next incoming connection whose handshake completes. OK: handles[0] is the wi_connection,
 * bytes the caller's 32-byte Ed25519 key as the handshake verified it. CLOSED once the endpoint
 * is closed. */
uint64_t wi_endpoint_accept(const wi_endpoint *endpoint, wi_callback callback, void *context);

/* Tells iroh the network may have changed. OK when iroh has taken it in. */
uint64_t wi_endpoint_network_change(const wi_endpoint *endpoint, wi_callback callback,
                                    void *context);

typedef struct wi_relay_state {
  bool connected;
  /* NUL-terminated, truncated to fit. */
  char url[256];
  char last_error[256];
} wi_relay_state;

/* The home relay's state now; false before the endpoint has picked its home relay. */
bool wi_endpoint_relay_state(const wi_endpoint *endpoint, wi_relay_state *out);

/* A cursor over the home relay state's changes from now on, for wi_watch_next; NULL on failure.
 * Every cursor sees every change. */
wi_watch *wi_endpoint_relay_watch(const wi_endpoint *endpoint);

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
  /* The relay URL or the remote IP address and port, NUL-terminated, truncated to fit. */
  char remote[256];
} wi_path;

/* The path the connection sends on now; false when it has none or is closed. */
bool wi_connection_path(const wi_connection *connection, wi_path *out);

/* A cursor over the connection's path events (a path opened, closed or was selected) from now on,
 * for wi_watch_next; NULL on failure. Every cursor sees every event. */
wi_watch *wi_connection_path_watch(const wi_connection *connection);

/* CLOSED when the connection closes: code is the peer's application close code, or ours as given
 * to wi_connection_close, 0 for any other cause; message the peer's reason or the cause (empty
 * for our own close). */
uint64_t wi_connection_closed(const wi_connection *connection, wi_callback callback,
                              void *context);

void wi_connection_close(const wi_connection *connection, uint64_t code);

/* Drops this handle; the connection closes once nothing holds it (streams and operations
 * included). */
void wi_connection_free(wi_connection *connection);

/* ---- Streams ----------------------------------------------------------------------------- */

/* Writes all `len` bytes (copied before return). OK once QUIC flow control has taken them all.
 * STOPPED: code. CLOSED or ERROR: message. One pending write per stream. */
uint64_t wi_send_write(const wi_send *send, const uint8_t *bytes, size_t len,
                       wi_callback callback, void *context);

/* Ends the stream after what was written. OK; CLOSED when it is already finished or reset; ERROR,
 * finishing nothing, while a write is pending (from its call until its callback). */
wi_status wi_send_finish(const wi_send *send);

/* Abandons the stream with `code` once no write is pending (cancel a pending write first). */
void wi_send_reset(const wi_send *send, uint64_t code);

/* STOPPED once the peer stops the stream: code. FINISHED once a finished stream's data is all
 * acknowledged. CLOSED when the connection is lost first: message. Any number may be pending. */
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
 * decides whether it is admitted; on_disconnect runs exactly once for each admitted connection
 * when it ends. `connection` is unique per process. Both may run concurrently on runtime threads.
 * release(context) runs once, after the last callback, when the relay is gone. */
typedef struct wi_relay_access {
  void *context;
  bool (*on_connect)(void *context, const uint8_t public_key[32], uint64_t connection);
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
