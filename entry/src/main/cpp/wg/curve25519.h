/*
 * X25519 (RFC 7748) — Montgomery ladder over GF(2^255 - 19).
 *
 * Field elements use five 51-bit limbs held in uint64_t, the classic
 * "donna-c64" layout: cheap carries, and 64x64->128 multiplication maps
 * directly onto AArch64's umulh. Requires a compilers that implements
 * __uint128_t (clang/gcc both do).
 */
#ifndef WG_CURVE25519_H
#define WG_CURVE25519_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* out = X25519(scalar, point); returns 0, or -1 if the result is all-zero
 * (i.e. the peer supplied a low-order point). */
int x25519_scalarmult(uint8_t out[32],
                      const uint8_t scalar[32],
                      const uint8_t point[32]);

/* Derive the public key from a private key: X25519(priv, basepoint 9). */
int x25519_public_from_private(uint8_t pub[32], const uint8_t priv[32]);

/* Fill buf with cryptographically secure random bytes. Returns 0 on success. */
int wg_random_bytes(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WG_CURVE25519_H */
