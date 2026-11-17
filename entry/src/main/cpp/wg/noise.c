#include "noise.h"
#include "blake2s.h"
#include "chacha20poly1305.h"
#include "curve25519.h"

#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#endif

static const uint8_t CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const uint8_t IDENTIFIER[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const uint8_t MAC1_LABEL[] = "mac1----";

/* ── primitives ── */

static void mix_hash(uint8_t h[32], const uint8_t *data, size_t len) {
    blake2s_ctx c;
    blake2s_init(&c, 32);
    blake2s_update(&c, h, 32);
    blake2s_update(&c, data, len);
    blake2s_final(&c, h);
}

/* ck = KDF1(ck, input); tail = T1 */
static void kdf1(uint8_t ck[32], const uint8_t *input, size_t inlen) {
    uint8_t prk[32];
    uint8_t t1[32];
    static const uint8_t one = 0x01;

    hmac_blake2s(prk, ck, 32, input, inlen);
    hmac_blake2s(t1, prk, 32, &one, 1);
    memcpy(ck, t1, 32);

    wg_memzero(prk, sizeof(prk));
    wg_memzero(t1, sizeof(t1));
}

/* ck = T1, k1 = T2 */
static void kdf2(uint8_t ck[32], uint8_t k1[32],
                 const uint8_t *input, size_t inlen) {
    uint8_t prk[32];
    uint8_t buf[33];
    uint8_t t1[32];
    uint8_t t2[32];

    hmac_blake2s(prk, ck, 32, input, inlen);
    buf[0] = 0x01;
    hmac_blake2s(t1, prk, 32, buf, 1);
    memcpy(buf, t1, 32);
    buf[32] = 0x02;
    hmac_blake2s(t2, prk, 32, buf, 33);

    memcpy(ck, t1, 32);
    memcpy(k1, t2, 32);

    wg_memzero(prk, sizeof(prk));
    wg_memzero(buf, sizeof(buf));
    wg_memzero(t1, sizeof(t1));
    wg_memzero(t2, sizeof(t2));
}

/* ck = T1, t1_out = T2 (tau), k = T3 */
static void kdf3(uint8_t ck[32], uint8_t tau[32], uint8_t k[32],
                 const uint8_t *input, size_t inlen) {
    uint8_t prk[32];
    uint8_t buf[33];
    uint8_t t1[32];
    uint8_t t2[32];
    uint8_t t3[32];

    hmac_blake2s(prk, ck, 32, input, inlen);
    buf[0] = 0x01;
    hmac_blake2s(t1, prk, 32, buf, 1);
    memcpy(buf, t1, 32);
    buf[32] = 0x02;
    hmac_blake2s(t2, prk, 32, buf, 33);
    memcpy(buf, t2, 32);
    buf[32] = 0x03;
    hmac_blake2s(t3, prk, 32, buf, 33);

    memcpy(ck, t1, 32);
    memcpy(tau, t2, 32);
    memcpy(k, t3, 32);

    wg_memzero(prk, sizeof(prk));
    wg_memzero(buf, sizeof(buf));
    wg_memzero(t1, sizeof(t1));
    wg_memzero(t2, sizeof(t2));
    wg_memzero(t3, sizeof(t3));
}

/* ck = T1, k1 = T2, k2 = T3 (used to split the final transport keypair) */
/*
 * Transport key split for the initiator.
 *
 * wireguard-go: KDF2(&sendKey, &recvKey, chainKey, nil), and KDF2 assigns
 * dst1 = t1, dst2 = t2. So the initiator sends with t1 and receives with t2.
 * (The responder does the mirror image: KDF2(&recvKey, &sendKey, ...).)
 *
 * Getting this off by one - using t2/t3 as wireguard-go's KDF3 numbering
 * would suggest - produces a handshake that authenticates perfectly and then
 * fails on every single transport packet, which is a miserable bug to find.
 */
static void kdf2_keys(uint8_t ck[32], uint8_t k1[32], uint8_t k2[32],
                      const uint8_t *input, size_t inlen) {
    uint8_t prk[32];
    uint8_t buf[33];
    uint8_t t1[32];
    uint8_t t2[32];

    hmac_blake2s(prk, ck, 32, input, inlen);
    buf[0] = 0x01;
    hmac_blake2s(t1, prk, 32, buf, 1);
    memcpy(buf, t1, 32);
    buf[32] = 0x02;
    hmac_blake2s(t2, prk, 32, buf, 33);

    memcpy(ck, t1, 32);
    memcpy(k1, t1, 32);
    memcpy(k2, t2, 32);

    wg_memzero(prk, sizeof(prk));
    wg_memzero(buf, sizeof(buf));
    wg_memzero(t1, sizeof(t1));
    wg_memzero(t2, sizeof(t2));
}

static uint32_t load32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* AEAD with the handshake's zero nonce. */
static void aead_seal(uint8_t *dst, const uint8_t key[32],
                      const uint8_t *pt, size_t ptlen,
                      const uint8_t *ad, size_t adlen) {
    static const uint8_t zero_nonce[12] = { 0 };
    chacha20poly1305_seal(dst, pt, ptlen, ad, adlen, zero_nonce, key);
}

static int aead_open(uint8_t *dst, const uint8_t key[32],
                     const uint8_t *ct, size_t ctlen,
                     const uint8_t *ad, size_t adlen) {
    static const uint8_t zero_nonce[12] = { 0 };
    return chacha20poly1305_open(dst, ct, ctlen, ad, adlen, zero_nonce, key);
}

/* ── timestamp ── */

void wg_tai64n_now(uint8_t out[12]) {
    uint64_t sec;
    uint32_t nsec;

#if defined(_WIN32)
    {
        FILETIME ft;
        ULARGE_INTEGER u;
        GetSystemTimeAsFileTime(&ft);
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        /* 100-ns ticks since 1601-01-01 -> since 1970-01-01 */
        u.QuadPart -= 116444736000000000ULL;
        sec = u.QuadPart / 10000000ULL;
        nsec = (uint32_t)((u.QuadPart % 10000000ULL) * 100ULL);
    }
#else
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        sec = (uint64_t)ts.tv_sec;
        nsec = (uint32_t)ts.tv_nsec;
    }
#endif

    sec += 0x4000000000000000ULL; /* TAI64 offset */

    out[0] = (uint8_t)(sec >> 56);
    out[1] = (uint8_t)(sec >> 48);
    out[2] = (uint8_t)(sec >> 40);
    out[3] = (uint8_t)(sec >> 32);
    out[4] = (uint8_t)(sec >> 24);
    out[5] = (uint8_t)(sec >> 16);
    out[6] = (uint8_t)(sec >> 8);
    out[7] = (uint8_t)(sec);
    out[8]  = (uint8_t)(nsec >> 24);
    out[9]  = (uint8_t)(nsec >> 16);
    out[10] = (uint8_t)(nsec >> 8);
    out[11] = (uint8_t)(nsec);
}

/* ── handshake ── */

void wg_handshake_init(wg_handshake *hs,
                       const uint8_t local_priv[32],
                       const uint8_t local_pub[32],
                       const uint8_t remote_pub[32],
                       const uint8_t psk[32]) {
    memset(hs, 0, sizeof(*hs));
    memcpy(hs->local_static_priv, local_priv, 32);
    memcpy(hs->local_static_pub, local_pub, 32);
    memcpy(hs->remote_static_pub, remote_pub, 32);
    if (psk) memcpy(hs->psk, psk, 32);
    hs->state = WG_HS_IDLE;
}

int wg_handshake_create_initiation(wg_handshake *hs, uint8_t out[WG_INITIATION_LEN]) {
    uint8_t dh[32];
    uint8_t key[32];
    uint8_t enc_static[48];
    uint8_t enc_timestamp[28];
    uint8_t timestamp[12];
    uint8_t mac1_key[32];
    uint8_t mac1_input[64];
    blake2s_ctx c;
    uint32_t idx;

    /* ck = HASH(CONSTRUCTION); h = HASH(ck || IDENTIFIER) */
    blake2s_hash(hs->chaining_key, 32, CONSTRUCTION, sizeof(CONSTRUCTION) - 1);
    blake2s_init(&c, 32);
    blake2s_update(&c, hs->chaining_key, 32);
    blake2s_update(&c, IDENTIFIER, sizeof(IDENTIFIER) - 1);
    blake2s_final(&c, hs->hash);

    /* h = HASH(h || Sr) */
    mix_hash(hs->hash, hs->remote_static_pub, 32);

    /* -> e */
    if (wg_random_bytes(hs->eph_priv, 32) != 0) return -1;
    if (x25519_public_from_private(hs->eph_pub, hs->eph_priv) != 0) return -1;

    kdf1(hs->chaining_key, hs->eph_pub, 32);
    mix_hash(hs->hash, hs->eph_pub, 32);

    /* -> es: ck, k = KDF2(ck, DH(Ei, Sr)) */
    if (x25519_scalarmult(dh, hs->eph_priv, hs->remote_static_pub) != 0) return -1;
    kdf2(hs->chaining_key, key, dh, 32);
    aead_seal(enc_static, key, hs->local_static_pub, 32, hs->hash, 32);
    mix_hash(hs->hash, enc_static, 48);

    /* -> ss: ck, k = KDF2(ck, DH(Si, Sr)) */
    if (x25519_scalarmult(dh, hs->local_static_priv, hs->remote_static_pub) != 0) return -1;
    kdf2(hs->chaining_key, key, dh, 32);

    wg_tai64n_now(timestamp);
    aead_seal(enc_timestamp, key, timestamp, 12, hs->hash, 32);
    mix_hash(hs->hash, enc_timestamp, 28);

    /* assemble */
    if (wg_random_bytes(&idx, sizeof(idx)) != 0) return -1;
    hs->local_index = idx;

    store32le(out + 0, 1);
    store32le(out + 4, hs->local_index);
    memcpy(out + 8, hs->eph_pub, 32);
    memcpy(out + 40, enc_static, 48);
    memcpy(out + 88, enc_timestamp, 28);

    /* mac1 = keyed BLAKE2s-128(key = HASH("mac1----" || Sr), msg[0..116]) */
    blake2s_init(&c, 32);
    blake2s_update(&c, MAC1_LABEL, 8);
    blake2s_update(&c, hs->remote_static_pub, 32);
    blake2s_final(&c, mac1_key);
    blake2s_hash_keyed(mac1_input, 16, mac1_key, 32, out, 116);
    memcpy(out + 116, mac1_input, 16);

    /* mac2 = zeros (no cookie) */
    memset(out + 132, 0, 16);

    hs->state = WG_HS_WAITING_RESPONSE;

    wg_memzero(dh, sizeof(dh));
    wg_memzero(key, sizeof(key));
    wg_memzero(mac1_key, sizeof(mac1_key));
    wg_memzero(timestamp, sizeof(timestamp));
    return 0;
}

int wg_handshake_consume_response(wg_handshake *hs, const uint8_t *msg, size_t len) {
    uint8_t dh[32];
    uint8_t tau[32];
    uint8_t key[32];
    uint8_t plain[16];
    uint32_t receiver_idx;
    const uint8_t *peer_eph;
    const uint8_t *empty_ct;

    if (hs->state != WG_HS_WAITING_RESPONSE) return -1;
    if (len < WG_RESPONSE_LEN) return -2;

    if (load32le(msg) != 2) return -2;

    receiver_idx = load32le(msg + 8);
    if (receiver_idx != hs->local_index) return -3;

    hs->remote_index = load32le(msg + 4);
    peer_eph = msg + 12;
    empty_ct = msg + 44;

    /* mixHash(Er); mixKey(Er) */
    mix_hash(hs->hash, peer_eph, 32);
    kdf1(hs->chaining_key, peer_eph, 32);

    /* ee */
    if (x25519_scalarmult(dh, hs->eph_priv, peer_eph) != 0) goto fail;
    kdf1(hs->chaining_key, dh, 32);

    /* se */
    if (x25519_scalarmult(dh, hs->local_static_priv, peer_eph) != 0) goto fail;
    kdf1(hs->chaining_key, dh, 32);

    /*
     * psk — unconditional. With no configured PSK this is KDF3 over 32 zero
     * bytes, exactly as every real WireGuard peer does it.
     */
    kdf3(hs->chaining_key, tau, key, hs->psk, 32);
    mix_hash(hs->hash, tau, 32);

    /* the empty payload must authenticate, and must decrypt to nothing */
    if (aead_open(plain, key, empty_ct, 16, hs->hash, 32) != 0) goto fail;
    mix_hash(hs->hash, empty_ct, 16);

    /* split into transport keys */
    kdf2_keys(hs->chaining_key, hs->send_key, hs->recv_key, NULL, 0);

    hs->send_counter = 0;
    hs->recv_counter = 0;
    hs->state = WG_HS_COMPLETE;

    wg_memzero(dh, sizeof(dh));
    wg_memzero(tau, sizeof(tau));
    wg_memzero(key, sizeof(key));
    wg_memzero(plain, sizeof(plain));
    return 0;

fail:
    hs->state = WG_HS_FAILED;
    wg_memzero(dh, sizeof(dh));
    wg_memzero(tau, sizeof(tau));
    wg_memzero(key, sizeof(key));
    wg_memzero(plain, sizeof(plain));
    return -4;
}
