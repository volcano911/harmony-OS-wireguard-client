#include "blake2s.h"

#include <string.h>

/* ── little-endian load/store, byte-oriented so it is alignment-safe ── */

static uint32_t load32(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32(void *dst, uint32_t v) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void wg_memzero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* ── state ── */

static const uint32_t blake2s_iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0}
};

static uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

#define G(a, b, c, d, x, y)          \
    do {                             \
        a = a + b + (x);             \
        d = rotr32(d ^ a, 16);       \
        c = c + d;                   \
        b = rotr32(b ^ c, 12);       \
        a = a + b + (y);             \
        d = rotr32(d ^ a, 8);        \
        c = c + d;                   \
        b = rotr32(b ^ c, 7);        \
    } while (0)

static void blake2s_compress(blake2s_ctx *c, const uint8_t block[64]) {
    uint32_t m[16];
    uint32_t v[16];
    int i, r;

    for (i = 0; i < 16; i++) m[i] = load32(block + 4 * i);

    for (i = 0; i < 8; i++) v[i] = c->h[i];
    v[8]  = blake2s_iv[0];
    v[9]  = blake2s_iv[1];
    v[10] = blake2s_iv[2];
    v[11] = blake2s_iv[3];
    v[12] = blake2s_iv[4] ^ c->t[0];
    v[13] = blake2s_iv[5] ^ c->t[1];
    v[14] = blake2s_iv[6] ^ c->f[0];
    v[15] = blake2s_iv[7] ^ c->f[1];

    for (r = 0; r < 10; r++) {
        const uint8_t *s = blake2s_sigma[r];
        G(v[0], v[4], v[8],  v[12], m[s[0]],  m[s[1]]);
        G(v[1], v[5], v[9],  v[13], m[s[2]],  m[s[3]]);
        G(v[2], v[6], v[10], v[14], m[s[4]],  m[s[5]]);
        G(v[3], v[7], v[11], v[15], m[s[6]],  m[s[7]]);
        G(v[0], v[5], v[10], v[15], m[s[8]],  m[s[9]]);
        G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        G(v[2], v[7], v[8],  v[13], m[s[12]], m[s[13]]);
        G(v[3], v[4], v[9],  v[14], m[s[14]], m[s[15]]);
    }

    for (i = 0; i < 8; i++) c->h[i] ^= v[i] ^ v[i + 8];
}

/* ── public API ── */

void blake2s_init(blake2s_ctx *c, size_t outlen) {
    int i;
    if (outlen == 0 || outlen > BLAKE2S_OUTBYTES) outlen = BLAKE2S_OUTBYTES;
    memset(c, 0, sizeof(*c));
    for (i = 0; i < 8; i++) c->h[i] = blake2s_iv[i];
    /* parameter block: digest_length | key_length << 8 | fanout=1 | depth=1 */
    c->h[0] ^= 0x01010000u ^ (uint32_t)outlen;
    c->outlen = outlen;
}

void blake2s_init_key(blake2s_ctx *c, size_t outlen,
                      const void *key, size_t keylen) {
    uint8_t block[BLAKE2S_BLOCKBYTES];
    if (key == NULL || keylen == 0 || keylen > BLAKE2S_OUTBYTES) {
        blake2s_init(c, outlen);
        return;
    }
    if (outlen == 0 || outlen > BLAKE2S_OUTBYTES) outlen = BLAKE2S_OUTBYTES;
    memset(c, 0, sizeof(*c));
    {
        int i;
        for (i = 0; i < 8; i++) c->h[i] = blake2s_iv[i];
    }
    c->h[0] ^= 0x01010000u ^ ((uint32_t)keylen << 8) ^ (uint32_t)outlen;
    c->outlen = outlen;

    /* The key is padded to a full block and processed as the first block. */
    memset(block, 0, sizeof(block));
    memcpy(block, key, keylen);
    blake2s_update(c, block, sizeof(block));
    wg_memzero(block, sizeof(block));
}

void blake2s_update(blake2s_ctx *c, const void *in, size_t inlen) {
    const uint8_t *p = (const uint8_t *)in;
    if (inlen == 0) return;

    {
        size_t left = c->buflen;
        size_t fill = BLAKE2S_BLOCKBYTES - left;

        if (inlen > fill) {
            c->buflen = 0;
            memcpy(c->buf + left, p, fill);
            c->t[0] += BLAKE2S_BLOCKBYTES;
            if (c->t[0] < BLAKE2S_BLOCKBYTES) c->t[1]++;
            blake2s_compress(c, c->buf);
            p += fill;
            inlen -= fill;

            while (inlen > BLAKE2S_BLOCKBYTES) {
                c->t[0] += BLAKE2S_BLOCKBYTES;
                if (c->t[0] < BLAKE2S_BLOCKBYTES) c->t[1]++;
                blake2s_compress(c, p);
                p += BLAKE2S_BLOCKBYTES;
                inlen -= BLAKE2S_BLOCKBYTES;
            }
        }
        memcpy(c->buf + c->buflen, p, inlen);
        c->buflen += inlen;
    }
}

void blake2s_final(blake2s_ctx *c, void *out) {
    uint8_t buffer[BLAKE2S_BLOCKBYTES];
    uint8_t full[BLAKE2S_OUTBYTES];
    size_t i;

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, c->buf, c->buflen);
    c->t[0] += (uint32_t)c->buflen;
    if (c->t[0] < c->buflen) c->t[1]++;
    c->f[0] = 0xffffffffu;
    blake2s_compress(c, buffer);

    for (i = 0; i < 8; i++) store32(full + 4 * i, c->h[i]);
    memcpy(out, full, c->outlen);

    wg_memzero(buffer, sizeof(buffer));
    wg_memzero(full, sizeof(full));
    wg_memzero(c, sizeof(*c));
}

void blake2s_hash(void *out, size_t outlen, const void *in, size_t inlen) {
    blake2s_ctx c;
    blake2s_init(&c, outlen);
    blake2s_update(&c, in, inlen);
    blake2s_final(&c, out);
}

void blake2s_hash_keyed(void *out, size_t outlen,
                        const void *key, size_t keylen,
                        const void *in, size_t inlen) {
    blake2s_ctx c;
    blake2s_init_key(&c, outlen, key, keylen);
    blake2s_update(&c, in, inlen);
    blake2s_final(&c, out);
}

/*
 * HMAC-BLAKE2s. wireguard-go builds its KDF on crypto/hmac with blake2s.New256,
 * i.e. plain HMAC with a 64-byte block, NOT keyed-BLAKE2s.
 */
void hmac_blake2s(uint8_t out[32],
                  const uint8_t *key, size_t keylen,
                  const uint8_t *msg, size_t msglen) {
    uint8_t k[BLAKE2S_BLOCKBYTES];
    uint8_t ipad[BLAKE2S_BLOCKBYTES];
    uint8_t opad[BLAKE2S_BLOCKBYTES];
    uint8_t inner[32];
    blake2s_ctx c;
    size_t i;

    memset(k, 0, sizeof(k));
    if (keylen > BLAKE2S_BLOCKBYTES) {
        blake2s_hash(k, 32, key, keylen);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }

    for (i = 0; i < BLAKE2S_BLOCKBYTES; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    blake2s_init(&c, 32);
    blake2s_update(&c, ipad, sizeof(ipad));
    blake2s_update(&c, msg, msglen);
    blake2s_final(&c, inner);

    blake2s_init(&c, 32);
    blake2s_update(&c, opad, sizeof(opad));
    blake2s_update(&c, inner, sizeof(inner));
    blake2s_final(&c, out);

    wg_memzero(k, sizeof(k));
    wg_memzero(ipad, sizeof(ipad));
    wg_memzero(opad, sizeof(opad));
    wg_memzero(inner, sizeof(inner));
}
