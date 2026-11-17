/*
 * WireGuard tunnel engine.
 *
 * Owns the whole data path: it polls the TUN fd and the UDP socket in one
 * thread, and every packet in between is touched only by C. ArkTS supplies
 * configuration and reads counters; it never sees a packet.
 */
#ifndef WG_TUNNEL_H
#define WG_TUNNEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    intptr_t tun_fd;         /* VpnConnection tunnel fd (or socket fd in tests) */
    const char *server_ip;   /* dotted IPv4 */
    int server_port;
    uint8_t client_priv[32];
    uint8_t server_pub[32];
    uint8_t psk[32];         /* 32 zero bytes when unset */
    uint8_t client_ip[4];    /* used to rewrite the TUN source address */
    int mtu;
} wg_tunnel_config;

typedef void (*wg_log_fn)(int level, const char *msg);

typedef struct {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_drops;
    uint64_t rx_drops;
    uint64_t decrypt_errors;
    uint64_t handshakes;
    uint64_t handshake_failures;
    uint64_t rekeys;
    uint64_t uptime_ms;
    uint64_t last_handshake_age_ms;
    int      connected;
    uint32_t local_index;
    uint32_t remote_index;
} wg_tunnel_stats;

/* Starts the engine. Returns 0 on success, negative errno-ish on failure. */
int  wg_tunnel_start(const wg_tunnel_config *cfg);
void wg_tunnel_stop(void);
int  wg_tunnel_is_running(void);
void wg_tunnel_get_stats(wg_tunnel_stats *out);

/* Optional diagnostics sink; levels are 0=error 1=warn 2=info 3=debug. */
void wg_tunnel_set_log(wg_log_fn fn);

#ifdef __cplusplus
}
#endif

#endif /* WG_TUNNEL_H */
