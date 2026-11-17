/*
 * BLAKE2s-256 / BLAKE2s-128 (RFC 7693), including keyed mode.
 *
 * WireGuard uses BLAKE2s in four places:
 *   1. Noise hash (mixHash)          -> unkeyed BLAKE2s-256
 *   2. HMAC-BLAKE2s inside the KDF   -> block size 64, unkeyed primitive
 *   3. MAC1 / MAC2                    -> *keyed* BLAKE2s-128
 *   4. Handshake prf + cookie MAC     -> unkeyed BLAKE2s-256
 *
 * All three modes are provided. Keyed mode is NOT the same construction as
 * HMAC; WireGuard needs both and they are not interchangeable.
 */
#ifndef WG_BLAKE2S_H
#define WG_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLAKE2S_BLOCKBYTES 64
#define BLAKE2S_OUTBYTES   32

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2S_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
} blake2s_ctx;

void blake2s_init(blake2s_ctx *c, size_t outlen);
void blake2s_init_key(blake2s_ctx *c, size_t outlen,
                      const void *key, size_t keylen);
void blake2s_update(blake2s_ctx *c, const void *in, size_t inlen);
void blake2s_final(blake2s_ctx *c, void *out);

/* One-shot helpers. */
void blake2s_hash(void *out, size_t outlen, const void *in, size_t inlen);
void blake2s_hash_keyed(void *out, size_t outlen,
                        const void *key, size_t keylen,
                        const void *in, size_t inlen);

/*
 * HMAC-BLAKE2s (RFC 2104) with the BLAKE2s block size of 64 bytes.
 * WireGuard's KDF/HKDF is built on this and on nothing else.
 */
void hmac_blake2s(uint8_t out[32],
                  const uint8_t *key, size_t keylen,
                  const uint8_t *msg, size_t msglen);

/* Wipe memory in a way the optimiser may not elide. */
void wg_memzero(void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* WG_BLAKE2S_H */
