/*
 * IPv4 packet surgery and the transport replay window.
 *
 * These are the two pieces of the data path that are easy to get subtly wrong
 * and impossible to debug from a phone: a bad checksum is silently dropped by
 * the peer's stack, and a bad replay window silently drops legitimate traffic.
 * Both are unit-tested against reference vectors on the build machine.
 */
#ifndef WG_PACKET_H
#define WG_PACKET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── little-endian helpers (WireGuard wire format) ── */

static inline uint32_t wg_load32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t wg_load64le(const uint8_t *p) {
    return (uint64_t)wg_load32le(p) | ((uint64_t)wg_load32le(p + 4) << 32);
}

static inline void wg_store32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void wg_store64le(uint8_t *p, uint64_t v) {
    wg_store32le(p, (uint32_t)v);
    wg_store32le(p + 4, (uint32_t)(v >> 32));
}

/* ── internet checksum (RFC 1071) ── */

uint32_t wg_checksum_partial(uint32_t sum, const uint8_t *data, size_t len);
uint16_t wg_checksum_fold(uint32_t sum);

/*
 * Rewrite the IPv4 source address in place and repair every checksum that
 * covers it (IP header, plus TCP/UDP when the packet is not a fragment tail).
 *
 * Returns 0 when the packet was rewritten or needed no change, -1 when it is
 * not a well-formed IPv4 packet that we can touch.
 */
int wg_snat_ipv4(uint8_t *pkt, size_t len, const uint8_t new_src[4]);

/* ── replay window (2048 bits, as specified for WireGuard) ── */

#define WG_REPLAY_BITS   2048
#define WG_REPLAY_WORDS  (WG_REPLAY_BITS / 64)

typedef struct {
    uint64_t last;
    uint64_t bitmap[WG_REPLAY_WORDS];
} wg_replay;

void wg_replay_reset(wg_replay *r);

/* Returns 1 when the counter is fresh (and records it), 0 on replay/too old. */
int wg_replay_validate(wg_replay *r, uint64_t counter);

#ifdef __cplusplus
}
#endif

#endif /* WG_PACKET_H */
