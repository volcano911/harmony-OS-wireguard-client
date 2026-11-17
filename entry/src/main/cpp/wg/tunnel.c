/*
 * The tunnel engine.
 *
 * One thread owns everything: it polls the TUN fd and the UDP socket, runs the
 * handshake state machine, and is the only code that ever touches a packet.
 * ArkTS hands over configuration, then reads counters. No packet crosses the
 * language boundary in either direction.
 */
#include "tunnel.h"
#include "noise.h"
#include "packet.h"
#include "blake2s.h"
#include "chacha20poly1305.h"
#include "curve25519.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET wg_sock;
typedef int wg_socklen;
#define WG_BAD_SOCK INVALID_SOCKET
#define wg_poll WSAPoll
#define wg_close_sock closesocket
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef int wg_sock;
typedef socklen_t wg_socklen;
#define WG_BAD_SOCK (-1)
#define wg_poll poll
#define wg_close_sock close
#endif

/* timers, all in milliseconds */
#ifndef REKEY_AFTER_MS
#define REKEY_AFTER_MS       120000u   /* renegotiate well before the 180s limit */
#endif
#ifndef REJECT_AFTER_MS
#define REJECT_AFTER_MS      180000u   /* peer silent this long -> session is dead */
#endif
#ifndef KEEPALIVE_MS
#define KEEPALIVE_MS          25000u
#endif
#ifndef HANDSHAKE_RETRY_MS
#define HANDSHAKE_RETRY_MS     5000u
#endif
#define HANDSHAKE_GIVE_UP        18    /* ~90s of silence before we say so */
#define POLL_SLICE_MS           100

#define MAX_HANDSHAKE_PACKET 148

typedef struct {
    wg_tunnel_config cfg;
    char server_ip[64];

    wg_sock sock;
    struct sockaddr_in peer;
    intptr_t tun;

    wg_handshake hs;
    wg_replay replay;
    int have_keys;

    volatile int stop;
    volatile int running;

    uint64_t started_ms;
    uint64_t last_init_ms;
    uint64_t last_send_ms;
    uint64_t last_recv_ms;
    uint64_t session_ms;
    uint64_t last_handshake_ms;
    int attempts;

    uint64_t tx_packets, tx_bytes;
    uint64_t rx_packets, rx_bytes;
    uint64_t tx_drops, rx_drops;
    uint64_t decrypt_errors;
    uint64_t handshakes, handshake_failures, rekeys;

    /*
     * Static rather than on the thread stack: a 64 KiB frame on the VpnExtension
     * thread is asking for trouble, and there is exactly one engine per process.
     */
    uint8_t rx[65536];
    uint8_t tx[65536 + 64];
} wg_engine;

static wg_engine g_e;
static wg_log_fn g_log;

#if defined(_WIN32)
static HANDLE g_thread;
static int g_thread_valid;
static int g_wsa_ready;
#else
static pthread_t g_thread;
static int g_thread_valid;
#endif

/* ── logging ── */

static void logmsg(int level, const char *fmt, ...) {
    char buf[320];
    va_list ap;

    if (!g_log) return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_log(level, buf);
}

/* ── platform helpers ── */

static uint64_t now_ms(void) {
#if defined(_WIN32)
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

/*
 * The tunnel fd is a character device on device and a connected socket in the
 * test harness; both answer to read/write on POSIX. Windows needs recv/send
 * because its sockets are not CRT file descriptors.
 */
static int tun_read_bytes(intptr_t fd, void *buf, size_t len) {
#if defined(_WIN32)
    return recv((SOCKET)fd, (char *)buf, (int)len, 0);
#else
    int n;
    do {
        n = (int)read((int)fd, buf, len);
    } while (n < 0 && errno == EINTR);
    return n;
#endif
}

static int tun_write_bytes(intptr_t fd, const void *buf, size_t len) {
#if defined(_WIN32)
    return send((SOCKET)fd, (const char *)buf, (int)len, 0);
#else
    int n;
    do {
        n = (int)write((int)fd, buf, len);
    } while (n < 0 && errno == EINTR);
    return n;
#endif
}

/* ── packet paths ── */

static int send_initiation(uint64_t now) {
    uint8_t msg[WG_INITIATION_LEN];
    int sent;

    if (wg_handshake_create_initiation(&g_e.hs, msg) != 0) {
        logmsg(0, "failed to build handshake initiation");
        return -1;
    }

    sent = (int)sendto(g_e.sock, (const char *)msg, (int)sizeof(msg), 0,
                       (const struct sockaddr *)&g_e.peer, sizeof(g_e.peer));
    if (sent != (int)sizeof(msg)) {
        logmsg(0, "handshake initiation send failed (%d)", sent);
        return -1;
    }

    g_e.last_init_ms = now;
    g_e.attempts++;
    logmsg(3, "handshake initiation #%d sent (idx=0x%08x)",
           g_e.attempts, (unsigned)g_e.hs.local_index);
    return 0;
}

static int send_transport(const uint8_t *plain, size_t len) {
    uint8_t nonce[12];
    uint8_t *pkt = g_e.tx;
    size_t total;
    int sent;

    if (!g_e.have_keys) return -1;

    wg_store32le(pkt, 4);
    wg_store32le(pkt + 4, g_e.hs.remote_index);
    wg_store64le(pkt + 8, g_e.hs.send_counter);

    memset(nonce, 0, 4);
    wg_store64le(nonce + 4, g_e.hs.send_counter);

    chacha20poly1305_seal(pkt + 16, plain, len, NULL, 0, nonce, g_e.hs.send_key);
    total = 16 + len + 16;

    sent = (int)sendto(g_e.sock, (const char *)pkt, (int)total, 0,
                       (const struct sockaddr *)&g_e.peer, sizeof(g_e.peer));
    g_e.hs.send_counter++;

    if (sent != (int)total) {
        /* 不要在这里刷新 last_send_ms：发包失败却记成「刚发过」，
         * 保活就会以为链路还好，一直空转到 180s 超时才重建。 */
        logmsg(1, "transport send failed (%d of %u)", sent, (unsigned)total);
        g_e.tx_drops++;
        return -1;
    }
    g_e.last_send_ms = now_ms();
    return 0;
}

static void send_keepalive(void) {
    static const uint8_t empty[1] = { 0 };
    send_transport(empty, 0);
    logmsg(3, "keepalive sent");
}

static void handle_response(const uint8_t *d, size_t len,
                            const struct sockaddr_in *src) {
    uint64_t now;

    if (g_e.hs.state != WG_HS_WAITING_RESPONSE) {
        logmsg(3, "unexpected handshake response, ignoring");
        return;
    }
    if (wg_handshake_consume_response(&g_e.hs, d, len) != 0) {
        g_e.handshake_failures++;
        logmsg(0, "handshake response rejected (decrypt failed)");
        return;
    }

    /* Only once the response authenticates do we trust where it came from:
     * roaming endpoints are fine, spoofed ones never get this far. */
    if (src != NULL && src->sin_family == AF_INET &&
        (src->sin_addr.s_addr != g_e.peer.sin_addr.s_addr ||
         src->sin_port != g_e.peer.sin_port)) {
        char from[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src->sin_addr, from, sizeof(from));
        g_e.peer = *src;
        logmsg(2, "peer endpoint moved to %s:%u", from,
               (unsigned)ntohs(src->sin_port));
    }

    now = now_ms();
    g_e.have_keys = 1;
    g_e.handshakes++;
    g_e.attempts = 0;
    g_e.session_ms = now;
    g_e.last_handshake_ms = now;
    g_e.last_recv_ms = now;
    wg_replay_reset(&g_e.replay);

    logmsg(2, "handshake complete (local=0x%08x remote=0x%08x)",
           (unsigned)g_e.hs.local_index, (unsigned)g_e.hs.remote_index);

    /* Prove liveness to the peer right away; this also seeds last_send_ms. */
    send_keepalive();
}

static void handle_transport(const uint8_t *d, size_t len) {
    uint8_t nonce[12];
    uint64_t counter;
    size_t ptlen;
    int n;

    if (!g_e.have_keys) {
        g_e.rx_drops++;
        return;
    }
    if (len < 32) {
        g_e.rx_drops++;
        return;
    }
    if (wg_load32le(d + 4) != g_e.hs.local_index) {
        /* belongs to a keypair we have already retired */
        g_e.rx_drops++;
        return;
    }

    counter = wg_load64le(d + 8);
    if (!wg_replay_validate(&g_e.replay, counter)) {
        g_e.rx_drops++;
        return;
    }

    memset(nonce, 0, 4);
    wg_store64le(nonce + 4, counter);

    if (chacha20poly1305_open(g_e.tx, d + 16, len - 16, NULL, 0, nonce,
                              g_e.hs.recv_key) != 0) {
        g_e.decrypt_errors++;
        g_e.rx_drops++;
        logmsg(1, "transport decrypt failed at counter %llu",
               (unsigned long long)counter);
        return;
    }

    ptlen = len - 32;
    g_e.last_recv_ms = now_ms();

    if (ptlen == 0) {
        logmsg(3, "keepalive received");
        return;
    }

    n = tun_write_bytes(g_e.tun, g_e.tx, ptlen);
    if (n != (int)ptlen) {
        g_e.rx_drops++;
        logmsg(1, "tun write failed (%d of %u)", n, (unsigned)ptlen);
        return;
    }
    g_e.rx_packets++;
    g_e.rx_bytes += ptlen;
}

static void handle_datagram(const uint8_t *d, size_t len,
                            const struct sockaddr_in *src) {
    uint32_t type;

    if (len < 4) {
        g_e.rx_drops++;
        return;
    }
    type = wg_load32le(d);

    switch (type) {
    case 2:
        handle_response(d, len, src);
        break;
    case 3:
        /* Under load a peer may demand a cookie. Not needed for a home router. */
        logmsg(1, "cookie reply received (unsupported), retrying plain");
        break;
    case 4:
        handle_transport(d, len);
        break;
    default:
        g_e.rx_drops++;
        break;
    }
}

static void drain_udp(void) {
    int i;

    for (i = 0; i < 128; i++) {
        struct sockaddr_in from;
        wg_socklen flen = (wg_socklen)sizeof(from);
        int n;

        memset(&from, 0, sizeof(from));
        n = (int)recvfrom(g_e.sock, (char *)g_e.rx, (int)sizeof(g_e.rx), 0,
                          (struct sockaddr *)&from, &flen);
        if (n <= 0) break;
        handle_datagram(g_e.rx, (size_t)n, &from);
    }
}

static void drain_tun(void) {
    int n = tun_read_bytes(g_e.tun, g_e.rx, sizeof(g_e.rx));
    size_t len;

    if (n <= 0) return;
    len = (size_t)n;

    if (!g_e.have_keys) {
        /* Traffic arrived before the tunnel is up: drop, and hurry the handshake. */
        g_e.tx_drops++;
        return;
    }

    if (wg_snat_ipv4(g_e.rx, len, g_e.cfg.client_ip) != 0) {
        g_e.tx_drops++;
        return;
    }

    if (send_transport(g_e.rx, len) == 0) {
        g_e.tx_packets++;
        g_e.tx_bytes += len;
    }
}

/* ── timers ── */

static void run_timers(uint64_t now) {
    if (!g_e.have_keys) {
        if (now - g_e.last_init_ms >= HANDSHAKE_RETRY_MS) {
            if (g_e.attempts >= HANDSHAKE_GIVE_UP) {
                g_e.handshake_failures++;
                g_e.attempts = 0;
                logmsg(1, "no handshake after %d attempts, still retrying",
                       HANDSHAKE_GIVE_UP);
            }
            send_initiation(now);
        }
        return;
    }

    if (g_e.hs.state == WG_HS_COMPLETE && now - g_e.session_ms >= REKEY_AFTER_MS) {
        g_e.rekeys++;
        logmsg(2, "rekeying");
        send_initiation(now);
        return;
    }

    if (g_e.hs.state == WG_HS_WAITING_RESPONSE &&
        now - g_e.last_init_ms >= HANDSHAKE_RETRY_MS) {
        send_initiation(now);
        return;
    }

    if (now - g_e.last_recv_ms >= REJECT_AFTER_MS) {
        logmsg(1, "peer silent for %us, restarting handshake",
               (unsigned)(REJECT_AFTER_MS / 1000u));
        g_e.have_keys = 0;
        send_initiation(now);
        return;
    }

    if (now - g_e.last_send_ms >= KEEPALIVE_MS) {
        send_keepalive();
    }
}

/* ── thread ── */

static void *worker(void *arg) {
    uint64_t now;

    (void)arg;
    g_e.running = 1;
    g_e.started_ms = now_ms();
    g_e.last_recv_ms = g_e.started_ms;
    g_e.last_send_ms = g_e.started_ms;

    logmsg(2, "engine started, server %s:%d mtu %d",
           g_e.server_ip, g_e.cfg.server_port, g_e.cfg.mtu);

    now = now_ms();
    send_initiation(now);
    g_e.last_init_ms = now;

    while (!g_e.stop) {
        int timeout;
        int n;
#if defined(_WIN32)
        WSAPOLLFD pfd[2];
#else
        struct pollfd pfd[2];
#endif

        now = now_ms();
        timeout = POLL_SLICE_MS;

#if defined(_WIN32)
        pfd[0].fd = (SOCKET)g_e.tun;
        pfd[1].fd = g_e.sock;
#else
        pfd[0].fd = (int)g_e.tun;
        pfd[1].fd = (int)g_e.sock;
#endif
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;
        pfd[1].events = POLLIN;
        pfd[1].revents = 0;

        n = wg_poll(pfd, 2, timeout);

        if (n > 0) {
            if (pfd[1].revents & POLLIN) drain_udp();
            if (pfd[0].revents & POLLIN) drain_tun();
        }

        run_timers(now_ms());
    }

    /* Tell the peer instead of letting it time out. */
    if (g_e.have_keys) send_keepalive();

    g_e.running = 0;
    return NULL;
}

#if defined(_WIN32)
static DWORD WINAPI win_worker(LPVOID arg) {
    worker(arg);
    return 0;
}
#endif

/* ── public API ── */

void wg_tunnel_set_log(wg_log_fn fn) {
    g_log = fn;
}

int wg_tunnel_is_running(void) {
    return g_e.running;
}

int wg_tunnel_start(const wg_tunnel_config *cfg) {
    uint8_t local_pub[32];

    if (!cfg || !cfg->server_ip) return -22;
    if (g_e.running) return -16;

    memset(&g_e, 0, sizeof(g_e));
    g_e.cfg = *cfg;
    /* 0 is a valid fd, so an all-zero struct must not look like a live socket. */
    g_e.sock = WG_BAD_SOCK;

    if (strlen(cfg->server_ip) >= sizeof(g_e.server_ip)) return -22;
    memcpy(g_e.server_ip, cfg->server_ip, strlen(cfg->server_ip) + 1);
    g_e.cfg.server_ip = g_e.server_ip;
    g_e.tun = cfg->tun_fd;
    if (g_e.cfg.mtu <= 0 || g_e.cfg.mtu > 1500) g_e.cfg.mtu = 1420;

#if defined(_WIN32)
    if (!g_wsa_ready) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
        g_wsa_ready = 1;
    }
#endif

    memset(&g_e.peer, 0, sizeof(g_e.peer));
    g_e.peer.sin_family = AF_INET;
    g_e.peer.sin_port = htons((uint16_t)cfg->server_port);
    if (inet_pton(AF_INET, g_e.server_ip, &g_e.peer.sin_addr) != 1) {
        logmsg(0, "server address '%s' is not a dotted IPv4", g_e.server_ip);
        return -22;
    }

    g_e.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_e.sock == WG_BAD_SOCK) {
        logmsg(0, "cannot create UDP socket");
        return -1;
    }
    /*
     * Deliberately NOT connect()ed.
     *
     * A connected UDP socket makes the kernel filter datagrams by source
     * address, and that breaks the moment the peer answers from a different
     * address than we dialled. That is the normal case when the domain
     * resolves to the router's WAN IP while the phone sits on the same LAN:
     * the router hairpins the packet into its local wg1, and the reply leaves
     * with the LAN address as source. The response is silently dropped and the
     * handshake retries forever. sendto()/recvfrom() accepts it, and the
     * endpoint is re-pinned only after a response authenticates.
     */

    /* Non-blocking so the worker can drain a burst without a second syscall. */
#if defined(_WIN32)
    {
        u_long nb = 1;
        ioctlsocket(g_e.sock, FIONBIO, &nb);
    }
#else
    fcntl((int)g_e.sock, F_SETFL, fcntl((int)g_e.sock, F_GETFL, 0) | O_NONBLOCK);
#endif

    x25519_public_from_private(local_pub, cfg->client_priv);
    wg_handshake_init(&g_e.hs, cfg->client_priv, local_pub, cfg->server_pub, cfg->psk);
    wg_replay_reset(&g_e.replay);

    g_e.stop = 0;
    g_e.running = 1;

#if defined(_WIN32)
    g_thread = CreateThread(NULL, 0, win_worker, NULL, 0, NULL);
    if (!g_thread) {
        g_e.running = 0;
        wg_close_sock(g_e.sock);
        g_e.sock = WG_BAD_SOCK;
        return -1;
    }
    g_thread_valid = 1;
#else
    if (pthread_create(&g_thread, NULL, worker, NULL) != 0) {
        g_e.running = 0;
        wg_close_sock(g_e.sock);
        g_e.sock = WG_BAD_SOCK;
        return -1;
    }
    g_thread_valid = 1;
#endif

    return 0;
}

void wg_tunnel_stop(void) {
    g_e.stop = 1;

    /* Never touch the thread handle unless start() actually created it. */
    if (g_thread_valid) {
#if defined(_WIN32)
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = NULL;
#else
        pthread_join(g_thread, NULL);
#endif
        g_thread_valid = 0;
    }

    if (g_e.sock != WG_BAD_SOCK) {
        wg_close_sock(g_e.sock);
        g_e.sock = WG_BAD_SOCK;
    }
    g_e.running = 0;
    g_e.have_keys = 0;
    logmsg(2, "engine stopped");

    wg_memzero(g_e.hs.send_key, 32);
    wg_memzero(g_e.hs.recv_key, 32);
}

void wg_tunnel_get_stats(wg_tunnel_stats *out) {
    uint64_t now;

    if (!out) return;
    memset(out, 0, sizeof(*out));

    now = now_ms();
    out->tx_packets = g_e.tx_packets;
    out->tx_bytes = g_e.tx_bytes;
    out->rx_packets = g_e.rx_packets;
    out->rx_bytes = g_e.rx_bytes;
    out->tx_drops = g_e.tx_drops;
    out->rx_drops = g_e.rx_drops;
    out->decrypt_errors = g_e.decrypt_errors;
    out->handshakes = g_e.handshakes;
    out->handshake_failures = g_e.handshake_failures;
    out->rekeys = g_e.rekeys;
    out->connected = (g_e.have_keys && g_e.hs.state == WG_HS_COMPLETE) ? 1 : 0;
    out->local_index = g_e.hs.local_index;
    out->remote_index = g_e.hs.remote_index;

    if (g_e.running && now >= g_e.started_ms) {
        out->uptime_ms = now - g_e.started_ms;
    }
    if (g_e.last_handshake_ms && now >= g_e.last_handshake_ms) {
        out->last_handshake_age_ms = now - g_e.last_handshake_ms;
    }
}
