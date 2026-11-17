/*
 * ChaCha20-Poly1305 AEAD (RFC 8439) plus the raw ChaCha20 keystream.
 */
#ifndef WG_CHACHA20POLY1305_H
#define WG_CHACHA20POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WG_AEAD_TAGLEN 16
#define WG_AEAD_NONCELEN 12
#define WG_AEAD_KEYLEN 32

/* Raw ChaCha20: out[i] = in[i] ^ keystream, counter is the initial block ctr. */
void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t key[32], const uint8_t nonce[12],
                  uint32_t counter);

/*
 * AEAD seal: writes len + 16 bytes to dst (ciphertext followed by tag).
 * dst and src may be the same buffer.
 */
void chacha20poly1305_seal(uint8_t *dst,
                           const uint8_t *src, size_t len,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t nonce[12],
                           const uint8_t key[32]);

/*
 * AEAD open: dst receives len - 16 bytes of plaintext.
 * Returns 0 on success, -1 if the tag does not verify (dst is left untouched
 * in that case up to the caller's own bookkeeping).
 */
int chacha20poly1305_open(uint8_t *dst,
                          const uint8_t *src, size_t len,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t nonce[12],
                          const uint8_t key[32]);

/* Best-effort constant-time compare. Returns 0 when equal. */
int wg_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* WG_CHACHA20POLY1305_H */
