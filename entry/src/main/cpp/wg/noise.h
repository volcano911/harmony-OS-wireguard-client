/*
 * WireGuard Noise IKpsk2 handshake (initiator only).
 *
 * Mirrors wireguard-go's CreateMessageInitiation / ConsumeMessageResponse,
 * with one deliberate correction: the PSK step is *unconditional*. A peer
 * with no preshared key configured uses 32 zero bytes, and that zero PSK
 * still feeds KDF3 and still mixes tau into the hash. Skipping the step when
 * the PSK is all-zero (as the ArkTS implementation did) produces a chain key
 * that diverges from every real WireGuard peer.
 */
#ifndef WG_NOISE_H
#define WG_NOISE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WG_INITIATION_LEN 148
/* type(4) + sender(4) + receiver(4) + ephemeral(32) + empty(16) */
#define WG_RESPONSE_LEN   60

enum {
    WG_HS_IDLE = 0,
    WG_HS_WAITING_RESPONSE = 1,
    WG_HS_COMPLETE = 2,
    WG_HS_FAILED = 3
};

typedef struct {
    /* long-term material, retained across rekeys */
    uint8_t local_static_priv[32];
    uint8_t local_static_pub[32];
    uint8_t remote_static_pub[32];
    uint8_t psk[32];

    /* per-handshake transcript */
    uint8_t chaining_key[32];
    uint8_t hash[32];
    uint8_t eph_priv[32];
    uint8_t eph_pub[32];

    uint32_t local_index;
    uint32_t remote_index;

    int state;

    /* transport keys — kept valid across a rekey until the new one completes */
    uint8_t send_key[32];
    uint8_t recv_key[32];
    uint64_t send_counter;
    uint64_t recv_counter;
} wg_handshake;

void wg_handshake_init(wg_handshake *hs,
                       const uint8_t local_priv[32],
                       const uint8_t local_pub[32],
                       const uint8_t remote_pub[32],
                       const uint8_t psk[32]);

/* Build an initiation message. Returns 0 on success. */
int wg_handshake_create_initiation(wg_handshake *hs, uint8_t out[WG_INITIATION_LEN]);

/* Process a response. Returns 0 on success, negative on failure. */
int wg_handshake_consume_response(wg_handshake *hs, const uint8_t *msg, size_t len);

/* TAI64N timestamp used inside the initiation message. */
void wg_tai64n_now(uint8_t out[12]);

#ifdef __cplusplus
}
#endif

#endif /* WG_NOISE_H */
