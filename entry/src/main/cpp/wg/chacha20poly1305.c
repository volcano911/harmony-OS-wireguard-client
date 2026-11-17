#include "chacha20poly1305.h"
#include "blake2s.h"

#include <string.h>

/* ── byte helpers ── */

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

int wg_ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0 ? 0 : -1;
}

/* ── ChaCha20 ── */

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define QR(a, b, c, d)          \
    do {                        \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d, 8);  \
        c += d; b ^= c; b = rotl32(b, 7);  \
    } while (0)

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    int i;

    for (i = 0; i < 16; i++) x[i] = in[i];

    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static void chacha20_init_state(uint32_t st[16], const uint8_t key[32],
                                const uint8_t nonce[12], uint32_t counter) {
    st[0] = 0x61707865u;
    st[1] = 0x3320646eu;
    st[2] = 0x79622d32u;
    st[3] = 0x6b206574u;
    st[4]  = load32(key + 0);
    st[5]  = load32(key + 4);
    st[6]  = load32(key + 8);
    st[7]  = load32(key + 12);
    st[8]  = load32(key + 16);
    st[9]  = load32(key + 20);
    st[10] = load32(key + 24);
    st[11] = load32(key + 28);
    st[12] = counter;
    st[13] = load32(nonce + 0);
    st[14] = load32(nonce + 4);
    st[15] = load32(nonce + 8);
}

void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t key[32], const uint8_t nonce[12],
                  uint32_t counter) {
    uint32_t st[16];
    uint32_t ks[16];
    uint8_t  stream[64];
    size_t   off = 0;
    int      i;

    chacha20_init_state(st, key, nonce, counter);

    while (off < len) {
        size_t n = len - off;
        if (n > 64) n = 64;

        chacha20_block(ks, st);
        for (i = 0; i < 16; i++) store32(stream + 4 * i, ks[i]);

        for (i = 0; i < (int)n; i++) out[off + i] = (uint8_t)(in[off + i] ^ stream[i]);

        off += n;
        st[12]++;
    }

    wg_memzero(st, sizeof(st));
    wg_memzero(ks, sizeof(ks));
    wg_memzero(stream, sizeof(stream));
}

/* ── Poly1305 (5 x 26-bit limbs, donna-32 style) ── */

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t   leftover;
    uint8_t  buffer[16];
} poly1305_state;

#define POLY_MASK26 0x3ffffffu

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    st->r[0] = (load32(key + 0)) & 0x3ffffff;
    st->r[1] = (load32(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (load32(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (load32(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (load32(key + 12) >> 8) & 0x00fffff;

    st->pad[0] = load32(key + 16);
    st->pad[1] = load32(key + 20);
    st->pad[2] = load32(key + 24);
    st->pad[3] = load32(key + 28);

    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
    st->leftover = 0;
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *m,
                            size_t bytes, uint32_t hibit) {
    const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2],
                   r3 = st->r[3], r4 = st->r[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2],
             h3 = st->h[3], h4 = st->h[4];

    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;

        h0 += (load32(m + 0)) & POLY_MASK26;
        h1 += (load32(m + 3) >> 2) & POLY_MASK26;
        h2 += (load32(m + 6) >> 4) & POLY_MASK26;
        h3 += (load32(m + 9) >> 6) & POLY_MASK26;
        h4 += (load32(m + 12) >> 8) | hibit;

        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) +
             ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) +
             ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) +
             ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) +
             ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) +
             ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) +
             ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) +
             ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) +
             ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) +
             ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) +
             ((uint64_t)h4 * r0);

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & POLY_MASK26;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & POLY_MASK26;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & POLY_MASK26;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & POLY_MASK26;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & POLY_MASK26;

        h0 += c * 5; c = h0 >> 26; h0 &= POLY_MASK26;
        h1 += c;

        m += 16;
        bytes -= 16;
    }

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2;
    st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(poly1305_state *st, const uint8_t *m, size_t bytes) {
    if (bytes == 0) return;

    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        st->leftover += want;
        m += want;
        bytes -= want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16, (uint32_t)1 << 24);
        st->leftover = 0;
    }

    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(st, m, want, (uint32_t)1 << 24);
        m += want;
        bytes -= want;
    }

    if (bytes) {
        memcpy(st->buffer + st->leftover, m, bytes);
        st->leftover += bytes;
    }
}

static void poly1305_finish(poly1305_state *st, uint8_t mac[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t mask;
    uint64_t f;

    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; i++) st->buffer[i] = 0;
        poly1305_blocks(st, st->buffer, 16, 0);
    }

    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2];
    h3 = st->h[3]; h4 = st->h[4];

    /* fully carry h */
    c = h1 >> 26; h1 &= POLY_MASK26; h2 += c;
    c = h2 >> 26; h2 &= POLY_MASK26; h3 += c;
    c = h3 >> 26; h3 &= POLY_MASK26; h4 += c;
    c = h4 >> 26; h4 &= POLY_MASK26; h0 += c * 5;
    c = h0 >> 26; h0 &= POLY_MASK26; h1 += c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= POLY_MASK26;
    g1 = h1 + c; c = g1 >> 26; g1 &= POLY_MASK26;
    g2 = h2 + c; c = g2 >> 26; g2 &= POLY_MASK26;
    g3 = h3 + c; c = g3 >> 26; g3 &= POLY_MASK26;
    g4 = h4 + c - (1u << 26);

    /* select h if h < p, else h + -p */
    mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % 2^128 */
    h0 = (h0 | (h1 << 26)) & 0xffffffffu;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffu;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffu;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffu;

    /* mac = (h + pad) % 2^128 */
    f = (uint64_t)h0 + st->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32(mac + 0,  h0);
    store32(mac + 4,  h1);
    store32(mac + 8,  h2);
    store32(mac + 12, h3);

    wg_memzero(st, sizeof(*st));
}

/* ── AEAD ── */

static void pad16(poly1305_state *st, size_t n) {
    static const uint8_t zeros[16] = { 0 };
    if (n & 15) poly1305_update(st, zeros, 16 - (n & 15));
}

static void aead_tag(uint8_t tag[16],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *ct, size_t ctlen,
                     const uint8_t polykey[32]) {
    poly1305_state st;
    uint8_t lens[16];

    poly1305_init(&st, polykey);
    poly1305_update(&st, ad, adlen);
    pad16(&st, adlen);
    poly1305_update(&st, ct, ctlen);
    pad16(&st, ctlen);

    store32(lens + 0, (uint32_t)adlen);
    store32(lens + 4, (uint32_t)((uint64_t)adlen >> 32));
    store32(lens + 8, (uint32_t)ctlen);
    store32(lens + 12, (uint32_t)((uint64_t)ctlen >> 32));
    poly1305_update(&st, lens, 16);

    poly1305_finish(&st, tag);
}

void chacha20poly1305_seal(uint8_t *dst,
                           const uint8_t *src, size_t len,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t nonce[12],
                           const uint8_t key[32]) {
    uint8_t polykey[64];
    uint8_t tag[16];

    /* block 0 supplies the one-time Poly1305 key */
    {
        uint32_t st[16], ks[16];
        uint8_t raw[64];
        int i;
        chacha20_init_state(st, key, nonce, 0);
        chacha20_block(ks, st);
        for (i = 0; i < 16; i++) store32(raw + 4 * i, ks[i]);
        memcpy(polykey, raw, 32);
        wg_memzero(st, sizeof(st));
        wg_memzero(ks, sizeof(ks));
        wg_memzero(raw, sizeof(raw));
    }

    chacha20_xor(dst, src, len, key, nonce, 1);

    aead_tag(tag, ad, adlen, dst, len, polykey);
    memcpy(dst + len, tag, 16);

    wg_memzero(polykey, sizeof(polykey));
    wg_memzero(tag, sizeof(tag));
}

int chacha20poly1305_open(uint8_t *dst,
                          const uint8_t *src, size_t len,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t nonce[12],
                          const uint8_t key[32]) {
    uint8_t polykey[64];
    uint8_t tag[16];
    size_t  ctlen;
    int     rc;

    if (len < 16) return -1;
    ctlen = len - 16;

    {
        uint32_t st[16], ks[16];
        uint8_t raw[64];
        int i;
        chacha20_init_state(st, key, nonce, 0);
        chacha20_block(ks, st);
        for (i = 0; i < 16; i++) store32(raw + 4 * i, ks[i]);
        memcpy(polykey, raw, 32);
        wg_memzero(st, sizeof(st));
        wg_memzero(ks, sizeof(ks));
        wg_memzero(raw, sizeof(raw));
    }

    aead_tag(tag, ad, adlen, src, ctlen, polykey);
    rc = wg_ct_equal(tag, src + ctlen, 16);

    if (rc == 0) chacha20_xor(dst, src, ctlen, key, nonce, 1);

    wg_memzero(polykey, sizeof(polykey));
    wg_memzero(tag, sizeof(tag));
    return rc;
}
