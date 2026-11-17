#include "packet.h"

#include <string.h>

/* ── checksum ── */

uint32_t wg_checksum_partial(uint32_t sum, const uint8_t *data, size_t len) {
    size_t i = 0;

    while (i + 1 < len) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
        i += 2;
    }
    if (i < len) {
        /* odd trailing byte is padded with a zero on the right */
        sum += (uint32_t)data[i] << 8;
    }
    return sum;
}

uint16_t wg_checksum_fold(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)(~sum & 0xffffu);
}

/*
 * RFC 1624 eq. 3:  HC' = ~(~HC + ~m + m')
 *
 * Incremental rather than a full recompute because a fragmented datagram may
 * not contain the whole transport segment, but the pseudo-header words that we
 * are changing are always present in the first fragment.
 */
static uint16_t csum_adjust(uint16_t old_csum, uint16_t old_word, uint16_t new_word) {
    uint32_t sum = (uint16_t)~old_csum;
    sum += (uint16_t)~old_word;
    sum += new_word;
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)(~sum & 0xffffu);
}

int wg_snat_ipv4(uint8_t *pkt, size_t len, const uint8_t new_src[4]) {
    size_t ihl, total, l4len, csum_off;
    uint8_t proto;
    uint16_t frag;
    uint8_t *l4;

    if (len < 20 || (pkt[0] >> 4) != 4) return -1;

    ihl = (size_t)(pkt[0] & 0x0f) * 4u;
    if (ihl < 20 || ihl > len) return -1;

    total = ((size_t)pkt[2] << 8) | pkt[3];
    if (total < ihl || total > len) total = len;

    if (memcmp(pkt + 12, new_src, 4) == 0) return 0; /* already right */

    proto = pkt[9];
    frag = (uint16_t)(((uint16_t)pkt[6] << 8) | pkt[7]);

    l4 = pkt + ihl;
    l4len = total - ihl;

    if ((frag & 0x1fff) == 0 && l4len >= 8) {
        if (proto == 17 && l4len >= 8) {
            csum_off = 6;
            /* a zero UDP checksum means "not computed" and must stay zero */
            if (l4[csum_off] != 0 || l4[csum_off + 1] != 0) {
                uint16_t c = (uint16_t)((l4[csum_off] << 8) | l4[csum_off + 1]);
                c = csum_adjust(c, (uint16_t)((pkt[12] << 8) | pkt[13]),
                                (uint16_t)((new_src[0] << 8) | new_src[1]));
                c = csum_adjust(c, (uint16_t)((pkt[14] << 8) | pkt[15]),
                                (uint16_t)((new_src[2] << 8) | new_src[3]));
                l4[csum_off] = (uint8_t)(c >> 8);
                l4[csum_off + 1] = (uint8_t)c;
            }
        } else if (proto == 6 && l4len >= 20) {
            csum_off = 16;
            uint16_t c = (uint16_t)((l4[csum_off] << 8) | l4[csum_off + 1]);
            c = csum_adjust(c, (uint16_t)((pkt[12] << 8) | pkt[13]),
                            (uint16_t)((new_src[0] << 8) | new_src[1]));
            c = csum_adjust(c, (uint16_t)((pkt[14] << 8) | pkt[15]),
                            (uint16_t)((new_src[2] << 8) | new_src[3]));
            l4[csum_off] = (uint8_t)(c >> 8);
            l4[csum_off + 1] = (uint8_t)c;
        }
        /* ICMP and everything else: checksum does not cover the IP header */
    }

    memcpy(pkt + 12, new_src, 4);

    /* IP header checksum: full recompute, it is at most 60 bytes */
    pkt[10] = 0;
    pkt[11] = 0;
    {
        uint16_t c = wg_checksum_fold(wg_checksum_partial(0, pkt, ihl));
        pkt[10] = (uint8_t)(c >> 8);
        pkt[11] = (uint8_t)c;
    }

    return 0;
}

/* ── replay window ── */

void wg_replay_reset(wg_replay *r) {
    memset(r, 0, sizeof(*r));
}

int wg_replay_validate(wg_replay *r, uint64_t counter) {
    uint64_t slot, bit;

    /*
     * Counter 0 is legitimate — it is the first transport message of a session,
     * since peers take the value *before* incrementing. A freshly reset window
     * has last == 0 and an empty bitmap, so 0 lands in the bitmap path below
     * and is accepted exactly once.
     */
    if (counter > r->last) {
        /*
         * Retire every 64-counter word we cross. Word indices are compared in
         * their *raw* (unwrapped) form, so crossing into word 32 reliably wipes
         * the ring slot that still holds counters 0..63 — comparing wrapped
         * indices would leave those stale bits in place and report live
         * counters as replays.
         */
        uint64_t old_word = r->last >> 6;
        uint64_t new_word = counter >> 6;
        uint64_t words = new_word - old_word;

        if (words >= WG_REPLAY_WORDS) {
            memset(r->bitmap, 0, sizeof(r->bitmap));
        } else {
            uint64_t i;
            for (i = 1; i <= words; i++) {
                r->bitmap[(old_word + i) & (WG_REPLAY_WORDS - 1)] = 0;
            }
        }
        r->last = counter;
    } else if (r->last - counter >= WG_REPLAY_BITS) {
        return 0; /* older than the window */
    }

    slot = (counter >> 6) & (WG_REPLAY_WORDS - 1);
    bit = 1ULL << (counter & 63);

    if (r->bitmap[slot] & bit) return 0;
    r->bitmap[slot] |= bit;
    return 1;
}
