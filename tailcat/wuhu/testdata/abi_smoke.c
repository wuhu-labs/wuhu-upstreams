#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "wuhu_tailcat.h"

#define CHECK(test) do { \
    if (!(test)) { fprintf(stderr, "line %d: %s\n", __LINE__, #test); exit(1); } \
} while (0)

static void ok(char *message) {
    if (message) {
        fprintf(stderr, "%s\n", message);
        wt_free(message);
        exit(1);
    }
}

static void fails(char *message) {
    CHECK(message != NULL);
    wt_free(message);
}

static void unhex(const char *text, uint8_t out[32]) {
    CHECK(strlen(text) == 64);
    for (int i = 0; i < 32; i++) CHECK(sscanf(text + 2 * i, "%2hhx", &out[i]) == 1);
}

static int allow(uintptr_t expected, const uint8_t peer[32]) {
    return memcmp((const void *)expected, peer, 32) == 0;
}

static void presence(uintptr_t context, const uint8_t peer[32], int connected) {
    (void)context; (void)peer; (void)connected;
}

static void expect_byte(int fd, char want) {
    char got = 0;
    CHECK(read(fd, &got, 1) == 1 && got == want);
}

struct accept_call {
    uintptr_t node;
    pthread_barrier_t ready;
    atomic_bool returned;
};

static void *blocked_accept(void *arg) {
    struct accept_call *call = arg;
    int fd = -42;
    uint8_t peer[32] = {42};
    pthread_barrier_wait(&call->ready);
    char *message = wt_node_accept(call->node, 0, &fd, peer);
    atomic_store(&call->returned, true);
    fails(message);
    CHECK(fd == -42 && memcmp(peer, (uint8_t[32]){42}, 32) == 0);
    return NULL;
}

int main(int argc, char **argv) {
    CHECK(argc == 4); // region JSON, local seed, other node's Ed25519 public key
    alarm(30);
    uint8_t seed[32], ed[32], peer[32] = {0}, from[32] = {0};
    unhex(argv[2], seed);
    unhex(argv[3], ed);
    ok(wt_peer_key(ed, peer));
    CHECK(memcmp(peer, (uint8_t[32]){0}, 32) != 0);

    uintptr_t node = 0, other = 0;
    ok(wt_node_v2(seed, argv[1], allow, (uintptr_t)peer, &node));
    CHECK(node != 0);
    fails(wt_node_v2(seed, argv[1], allow, (uintptr_t)peer, &other));
    CHECK(other == 0);

    int fd = -1;
    ok(wt_node_dial(node, peer, 12000, &fd));
    CHECK(fd >= 0);
    CHECK(write(fd, "D", 1) == 1);
    expect_byte(fd, 'd');
    CHECK(close(fd) == 0);

    fd = -1;
    ok(wt_node_accept(node, 12000, &fd, from));
    CHECK(fd >= 0 && memcmp(peer, from, 32) == 0);
    expect_byte(fd, 'A');
    CHECK(write(fd, "a", 1) == 1);
    CHECK(close(fd) == 0);

    struct accept_call pending = {.node = node, .returned = false};
    pthread_t thread;
    CHECK(pthread_barrier_init(&pending.ready, NULL, 2) == 0);
    CHECK(pthread_create(&thread, NULL, blocked_accept, &pending) == 0);
    pthread_barrier_wait(&pending.ready);
    struct timespec brief = {.tv_nsec = 100000000};
    while (nanosleep(&brief, &brief) != 0 && errno == EINTR) {}
    CHECK(!atomic_load(&pending.returned));
    wt_close(node);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(pthread_barrier_destroy(&pending.ready) == 0);

    fd = -42;
    fails(wt_node_dial(node, peer, 12000, &fd));
    CHECK(fd == -42);
    ok(wt_node_v2(seed, argv[1], allow, (uintptr_t)peer, &other));
    CHECK(other != 0 && other != node);
    wt_close(other);

    uintptr_t relay = 0;
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    ok(wt_relay(allow, presence, (uintptr_t)peer, &relay));
    CHECK(relay != 0);
    ok(wt_relay_serve(relay, pair[0]));
    expect_byte(pair[1], 1); // DERP FrameServerKey
    CHECK(fcntl(pair[0], F_GETFD) == -1 && errno == EBADF);
    wt_close(relay);
    fails(wt_relay_serve(relay, pair[1]));
    CHECK(close(pair[1]) == 0); // failed call did not consume the FD
    return 0;
}
