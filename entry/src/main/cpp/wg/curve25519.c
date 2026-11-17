#include "curve25519.h"
#include "blake2s.h"

#include <string.h>

#if !defined(__SIZEOF_INT128__)
#error "this implementation requires a compiler with __uint128_t"
#endif

typedef __uint128_t u128;

#define MASK51 0x7ffffffffffffULL /* (1 << 51) - 1 */

typedef struct {
    uint64_t v[5];
} fe;

static void fe_0(fe *h) {
    h->v[0] = h->v[1] = h->v[2] = h->v[3] = h->v[4] = 0;
}

static void fe_1(fe *h) {
    h->v[0] = 1;
    h->v[1] = h->v[2] = h->v[3] = h->v[4] = 0;
}

static void fe_copy(fe *h, const fe *f) { memcpy(h, f, sizeof(fe)); }

static void fe_add(fe *h, const fe *f, const fe *g) {
    h->v[0] = f->v[0] + g->v[0];
    h->v[1] = f->v[1] + g->v[1];
    h->v[2] = f->v[2] + g->v[2];
    h->v[3] = f->v[3] + g->v[3];
    h->v[4] = f->v[4] + g->v[4];
}

/*
 * h = f - g. Each limb gets a multiple of p folded in first so the
 * subtraction can never wrap: 2^54 = 8 * 2^51 = 8 * 19 (mod p) = 152.
 */
static void fe_sub(fe *h, const fe *f, const fe *g) {
    static const uint64_t two54m152 = (1ULL << 54) - 152;
    static const uint64_t two54m8 = (1ULL << 54) - 8;

    h->v[0] = f->v[0] + two54m152 - g->v[0];
    h->v[1] = f->v[1] + two54m8 - g->v[1];
    h->v[2] = f->v[2] + two54m8 - g->v[2];
    h->v[3] = f->v[3] + two54m8 - g->v[3];
    h->v[4] = f->v[4] + two54m8 - g->v[4];
}

static void fe_mul(fe *h, const fe *f, const fe *g) {
    uint64_t f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
    uint64_t g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4];
    u128 r0, r1, r2, r3, r4;
    uint64_t c;

    r0 = (u128)f0 * g0 + (u128)19 * ((u128)f1 * g4 + (u128)f2 * g3 +
                                     (u128)f3 * g2 + (u128)f4 * g1);
    r1 = (u128)f0 * g1 + (u128)f1 * g0 + (u128)19 * ((u128)f2 * g4 +
                                     (u128)f3 * g3 + (u128)f4 * g2);
    r2 = (u128)f0 * g2 + (u128)f1 * g1 + (u128)f2 * g0 + (u128)19 *
         ((u128)f3 * g4 + (u128)f4 * g3);
    r3 = (u128)f0 * g3 + (u128)f1 * g2 + (u128)f2 * g1 + (u128)f3 * g0 +
         (u128)19 * (u128)f4 * g4;
    r4 = (u128)f0 * g4 + (u128)f1 * g3 + (u128)f2 * g2 + (u128)f3 * g1 +
         (u128)f4 * g0;

    c = (uint64_t)(r0 >> 51); h->v[0] = (uint64_t)r0 & MASK51; r1 += c;
    c = (uint64_t)(r1 >> 51); h->v[1] = (uint64_t)r1 & MASK51; r2 += c;
    c = (uint64_t)(r2 >> 51); h->v[2] = (uint64_t)r2 & MASK51; r3 += c;
    c = (uint64_t)(r3 >> 51); h->v[3] = (uint64_t)r3 & MASK51; r4 += c;
    c = (uint64_t)(r4 >> 51); h->v[4] = (uint64_t)r4 & MASK51;

    h->v[0] += c * 19;
    c = h->v[0] >> 51;
    h->v[0] &= MASK51;
    h->v[1] += c;
}

static void fe_sq(fe *h, const fe *f) { fe_mul(h, f, f); }

static void fe_mul121666(fe *h, const fe *f) {
    u128 r0 = (u128)f->v[0] * 121666;
    u128 r1 = (u128)f->v[1] * 121666;
    u128 r2 = (u128)f->v[2] * 121666;
    u128 r3 = (u128)f->v[3] * 121666;
    u128 r4 = (u128)f->v[4] * 121666;
    uint64_t c;

    c = (uint64_t)(r0 >> 51); h->v[0] = (uint64_t)r0 & MASK51; r1 += c;
    c = (uint64_t)(r1 >> 51); h->v[1] = (uint64_t)r1 & MASK51; r2 += c;
    c = (uint64_t)(r2 >> 51); h->v[2] = (uint64_t)r2 & MASK51; r3 += c;
    c = (uint64_t)(r3 >> 51); h->v[3] = (uint64_t)r3 & MASK51; r4 += c;
    c = (uint64_t)(r4 >> 51); h->v[4] = (uint64_t)r4 & MASK51;

    h->v[0] += c * 19;
    c = h->v[0] >> 51;
    h->v[0] &= MASK51;
    h->v[1] += c;
}

/* h = f^(p-2) = f^(2^255 - 21), the standard ref10 addition chain. */
static void fe_invert(fe *out, const fe *z) {
    fe t0, t1, t2, t3;
    int i;

    fe_sq(&t0, z);                          /* 2 */
    fe_sq(&t1, &t0);                        /* 4 */
    fe_sq(&t1, &t1);                        /* 8 */
    fe_mul(&t1, z, &t1);                    /* 9 */
    fe_mul(&t0, &t0, &t1);                  /* 11 */
    fe_sq(&t2, &t0);                        /* 22 */
    fe_mul(&t1, &t1, &t2);                  /* 2^5 - 1 */

    fe_sq(&t2, &t1);
    for (i = 1; i < 5; i++) fe_sq(&t2, &t2); /* 2^10 - 2^5 */
    fe_mul(&t1, &t2, &t1);                   /* 2^10 - 1 */

    fe_sq(&t2, &t1);
    for (i = 1; i < 10; i++) fe_sq(&t2, &t2); /* 2^20 - 2^10 */
    fe_mul(&t2, &t2, &t1);                    /* 2^20 - 1 */

    fe_sq(&t3, &t2);
    for (i = 1; i < 20; i++) fe_sq(&t3, &t3); /* 2^40 - 2^20 */
    fe_mul(&t2, &t3, &t2);                    /* 2^40 - 1 */

    fe_sq(&t2, &t2);
    for (i = 1; i < 10; i++) fe_sq(&t2, &t2); /* 2^50 - 2^10 */
    fe_mul(&t1, &t2, &t1);                    /* 2^50 - 1 */

    fe_sq(&t2, &t1);
    for (i = 1; i < 50; i++) fe_sq(&t2, &t2); /* 2^100 - 2^50 */
    fe_mul(&t2, &t2, &t1);                    /* 2^100 - 1 */

    fe_sq(&t3, &t2);
    for (i = 1; i < 100; i++) fe_sq(&t3, &t3); /* 2^200 - 2^100 */
    fe_mul(&t2, &t3, &t2);                     /* 2^200 - 1 */

    fe_sq(&t2, &t2);
    for (i = 1; i < 50; i++) fe_sq(&t2, &t2); /* 2^250 - 2^50 */
    fe_mul(&t1, &t2, &t1);                    /* 2^250 - 1 */

    fe_sq(&t1, &t1);
    for (i = 1; i < 5; i++) fe_sq(&t1, &t1); /* 2^255 - 2^5 */
    fe_mul(out, &t1, &t0);                   /* 2^255 - 21 */
}

static void fe_cswap(fe *f, fe *g, uint64_t b) {
    uint64_t mask = (uint64_t)0 - b;
    int i;
    for (i = 0; i < 5; i++) {
        uint64_t x = (f->v[i] ^ g->v[i]) & mask;
        f->v[i] ^= x;
        g->v[i] ^= x;
    }
}

/* ── serialisation ── */

static void fe_frombytes(fe *h, const uint8_t s[32]) {
    uint64_t lo;

    lo = (uint64_t)s[0] | ((uint64_t)s[1] << 8) | ((uint64_t)s[2] << 16) |
         ((uint64_t)s[3] << 24) | ((uint64_t)s[4] << 32) | ((uint64_t)s[5] << 40) |
         ((uint64_t)s[6] << 48) | ((uint64_t)s[7] << 56);
    h->v[0] = lo & MASK51;

    lo = (uint64_t)s[6] | ((uint64_t)s[7] << 8) | ((uint64_t)s[8] << 16) |
         ((uint64_t)s[9] << 24) | ((uint64_t)s[10] << 32) | ((uint64_t)s[11] << 40) |
         ((uint64_t)s[12] << 48) | ((uint64_t)s[13] << 56);
    h->v[1] = (lo >> 3) & MASK51;

    lo = (uint64_t)s[12] | ((uint64_t)s[13] << 8) | ((uint64_t)s[14] << 16) |
         ((uint64_t)s[15] << 24) | ((uint64_t)s[16] << 32) | ((uint64_t)s[17] << 40) |
         ((uint64_t)s[18] << 48) | ((uint64_t)s[19] << 56);
    h->v[2] = (lo >> 6) & MASK51;

    lo = (uint64_t)s[19] | ((uint64_t)s[20] << 8) | ((uint64_t)s[21] << 16) |
         ((uint64_t)s[22] << 24) | ((uint64_t)s[23] << 32) | ((uint64_t)s[24] << 40) |
         ((uint64_t)s[25] << 48) | ((uint64_t)s[26] << 56);
    h->v[3] = (lo >> 1) & MASK51;

    lo = (uint64_t)s[24] | ((uint64_t)s[25] << 8) | ((uint64_t)s[26] << 16) |
         ((uint64_t)s[27] << 24) | ((uint64_t)s[28] << 32) | ((uint64_t)s[29] << 40) |
         ((uint64_t)s[30] << 48) | ((uint64_t)s[31] << 56);
    h->v[4] = (lo >> 12) & MASK51;
}

static void put_bits(uint8_t *out, uint64_t v, int bitoff, int nbits) {
    int i;
    for (i = 0; i < nbits; i++) {
        if ((v >> i) & 1ULL) out[(unsigned)(bitoff + i) >> 3] |=
            (uint8_t)(1u << ((unsigned)(bitoff + i) & 7u));
    }
}

static void fe_tobytes(uint8_t s[32], const fe *h) {
    uint64_t h0 = h->v[0], h1 = h->v[1], h2 = h->v[2], h3 = h->v[3], h4 = h->v[4];
    uint64_t c, q;
    uint8_t out[32];

    /* normalise limbs first so the p-comparison below is meaningful */
    c = h1 >> 51; h1 &= MASK51; h2 += c;
    c = h2 >> 51; h2 &= MASK51; h3 += c;
    c = h3 >> 51; h3 &= MASK51; h4 += c;
    c = h4 >> 51; h4 &= MASK51; h0 += c * 19;
    c = h0 >> 51; h0 &= MASK51; h1 += c;

    /* q = 1 iff the value is >= p */
    q = (h0 + 19) >> 51;
    q = (h1 + q) >> 51;
    q = (h2 + q) >> 51;
    q = (h3 + q) >> 51;
    q = (h4 + q) >> 51;

    h0 += 19 * q;
    h1 += h0 >> 51; h0 &= MASK51;
    h2 += h1 >> 51; h1 &= MASK51;
    h3 += h2 >> 51; h2 &= MASK51;
    h4 += h3 >> 51; h3 &= MASK51;
    h4 &= MASK51;

    memset(out, 0, sizeof(out));
    put_bits(out, h0, 0, 51);
    put_bits(out, h1, 51, 51);
    put_bits(out, h2, 102, 51);
    put_bits(out, h3, 153, 51);
    put_bits(out, h4, 204, 51);
    memcpy(s, out, 32);
}

/* ── ladder ── */

int x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    uint64_t swap = 0;
    int pos;
    int i, nonzero = 0;
    uint8_t zero[32];

    memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe_frombytes(&x1, point);
    fe_1(&x2);
    fe_0(&z2);
    fe_copy(&x3, &x1);
    fe_1(&z3);

    for (pos = 254; pos >= 0; --pos) {
        uint64_t b = (e[pos / 8] >> (pos & 7)) & 1;

        swap ^= b;
        fe_cswap(&x2, &x3, swap);
        fe_cswap(&z2, &z3, swap);
        swap = b;

        fe_sub(&tmp0, &x3, &z3);
        fe_sub(&tmp1, &x2, &z2);
        fe_add(&x2, &x2, &z2);
        fe_add(&z2, &x3, &z3);
        fe_mul(&z3, &tmp0, &x2);
        fe_mul(&z2, &z2, &tmp1);
        fe_sq(&tmp0, &tmp1);
        fe_sq(&tmp1, &x2);
        fe_add(&x3, &z3, &z2);
        fe_sub(&z2, &z3, &z2);
        fe_mul(&x2, &tmp1, &tmp0);
        fe_sub(&tmp1, &tmp1, &tmp0);
        fe_sq(&z2, &z2);
        fe_mul121666(&z3, &tmp1);
        fe_sq(&x3, &x3);
        fe_add(&tmp0, &tmp0, &z3);
        fe_mul(&z3, &x1, &z2);
        fe_mul(&z2, &tmp1, &tmp0);
    }

    fe_cswap(&x2, &x3, swap);
    fe_cswap(&z2, &z3, swap);

    fe_invert(&z2, &z2);
    fe_mul(&x2, &x2, &z2);
    fe_tobytes(out, &x2);

    memset(zero, 0, sizeof(zero));
    for (i = 0; i < 32; i++) nonzero |= out[i];

    wg_memzero(e, sizeof(e));
    wg_memzero(&x1, sizeof(x1)); wg_memzero(&x2, sizeof(x2));
    wg_memzero(&z2, sizeof(z2)); wg_memzero(&x3, sizeof(x3));
    wg_memzero(&z3, sizeof(z3)); wg_memzero(&tmp0, sizeof(tmp0));
    wg_memzero(&tmp1, sizeof(tmp1));

    return nonzero == 0 ? -1 : 0;
}

int x25519_public_from_private(uint8_t pub[32], const uint8_t priv[32]) {
    static const uint8_t basepoint[32] = { 9 };
    return x25519_scalarmult(pub, priv, basepoint);
}

/* ── randomness ── */

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
int wg_random_bytes(void *buf, size_t len) {
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
}
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
int wg_random_bytes(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n <= 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        got += (size_t)n;
    }
    close(fd);
    return 0;
}
#endif
