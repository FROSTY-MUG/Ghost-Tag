#include "blake2.h"
#include <string.h>

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static inline uint64_t rotr64(const uint64_t w, const unsigned c) {
    return (w >> c) | (w << (64 - c));
}

static inline void blake2b_set_lastnode(blake2b_state *S) {
    S->f[1] = (uint64_t)-1;
}

static inline void blake2b_set_lastblock(blake2b_state *S) {
    if (S->last_node) blake2b_set_lastnode(S);
    S->f[0] = (uint64_t)-1;
}

static inline void blake2b_increment_counter(blake2b_state *S, const uint64_t inc) {
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

static void blake2b_compress(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES]) {
    uint64_t m[16];
    uint64_t v[16];
    size_t i;

    for (i = 0; i < 16; ++i) {
        m[i] = ((uint64_t)block[i * 8 + 0])       |
               (((uint64_t)block[i * 8 + 1]) << 8)  |
               (((uint64_t)block[i * 8 + 2]) << 16) |
               (((uint64_t)block[i * 8 + 3]) << 24) |
               (((uint64_t)block[i * 8 + 4]) << 32) |
               (((uint64_t)block[i * 8 + 5]) << 40) |
               (((uint64_t)block[i * 8 + 6]) << 48) |
               (((uint64_t)block[i * 8 + 7]) << 56);
    }

    for (i = 0; i < 8; ++i) v[i] = S->h[i];
    v[ 8] = blake2b_IV[0];
    v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = S->t[0] ^ blake2b_IV[4];
    v[13] = S->t[1] ^ blake2b_IV[5];
    v[14] = S->f[0] ^ blake2b_IV[6];
    v[15] = S->f[1] ^ blake2b_IV[7];

#define G(r,i,a,b,c,d) \
    do { \
        a = a + b + m[blake2b_sigma[r][2*i+0]]; \
        d = rotr64(d ^ a, 32); \
        c = c + d; \
        b = rotr64(b ^ c, 24); \
        a = a + b + m[blake2b_sigma[r][2*i+1]]; \
        d = rotr64(d ^ a, 16); \
        c = c + d; \
        b = rotr64(b ^ c, 63); \
    } while(0)

#define ROUND(r) \
    do { \
        G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
        G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
        G(r,2,v[ 2],v[ 6],v[10],v[14]); \
        G(r,3,v[ 3],v[ 7],v[11],v[15]); \
        G(r,4,v[ 0],v[ 5],v[10],v[15]); \
        G(r,5,v[ 1],v[ 6],v[11],v[12]); \
        G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
        G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
    } while(0)

    ROUND(0); ROUND(1); ROUND(2); ROUND(3);
    ROUND(4); ROUND(5); ROUND(6); ROUND(7);
    ROUND(8); ROUND(9); ROUND(10); ROUND(11);

#undef G
#undef ROUND

    for (i = 0; i < 8; ++i) {
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
    }
}

int blake2b_init_param(blake2b_state *S, const blake2b_param *P) {
    const uint8_t *p = (const uint8_t *)P;
    size_t i;
    memset(S, 0, sizeof(blake2b_state));
    for (i = 0; i < 8; ++i) S->h[i] = blake2b_IV[i];
    for (i = 0; i < 8; ++i) {
        uint64_t word = ((uint64_t)p[i*8+0])       |
                        (((uint64_t)p[i*8+1]) << 8)  |
                        (((uint64_t)p[i*8+2]) << 16) |
                        (((uint64_t)p[i*8+3]) << 24) |
                        (((uint64_t)p[i*8+4]) << 32) |
                        (((uint64_t)p[i*8+5]) << 40) |
                        (((uint64_t)p[i*8+6]) << 48) |
                        (((uint64_t)p[i*8+7]) << 56);
        S->h[i] ^= word;
    }
    S->outlen = P->digest_length;
    return 0;
}

int blake2b_init(blake2b_state *S, size_t outlen) {
    blake2b_param P;
    if (!outlen || outlen > BLAKE2B_OUTBYTES) return -1;
    memset(&P, 0, sizeof(blake2b_param));
    P.digest_length = (uint8_t)outlen;
    P.fanout = 1;
    P.depth = 1;
    return blake2b_init_param(S, &P);
}

int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen) {
    blake2b_param P;
    uint8_t block[BLAKE2B_BLOCKBYTES];
    if (!outlen || outlen > BLAKE2B_OUTBYTES) return -1;
    if (!key || !keylen || keylen > BLAKE2B_KEYBYTES) return -1;
    memset(&P, 0, sizeof(blake2b_param));
    P.digest_length = (uint8_t)outlen;
    P.key_length = (uint8_t)keylen;
    P.fanout = 1;
    P.depth = 1;
    if (blake2b_init_param(S, &P) < 0) return -1;
    memset(block, 0, BLAKE2B_BLOCKBYTES);
    memcpy(block, key, keylen);
    blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
    return 0;
}

int blake2b_update(blake2b_state *S, const void *pin, size_t inlen) {
    const uint8_t *in = (const uint8_t *)pin;
    if (inlen == 0) return 0;
    while (inlen > 0) {
        size_t left = S->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;
        if (inlen > fill) {
            S->buflen = 0;
            memcpy(S->buf + left, in, fill);
            blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
            blake2b_compress(S, S->buf);
            in += fill;
            inlen -= fill;
        } else {
            memcpy(S->buf + left, in, inlen);
            S->buflen += inlen;
            in += inlen;
            inlen = 0;
        }
    }
    return 0;
}

int blake2b_final(blake2b_state *S, void *out, size_t outlen) {
    uint8_t buffer[BLAKE2B_OUTBYTES] = {0};
    size_t i;
    if (out == NULL || outlen < S->outlen) return -1;
    if (S->buflen > 0) {
        blake2b_increment_counter(S, S->buflen);
        memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    }
    blake2b_set_lastblock(S);
    blake2b_compress(S, S->buf);
    for (i = 0; i < 8; ++i) {
        buffer[i * 8 + 0] = (uint8_t)(S->h[i] >>  0);
        buffer[i * 8 + 1] = (uint8_t)(S->h[i] >>  8);
        buffer[i * 8 + 2] = (uint8_t)(S->h[i] >> 16);
        buffer[i * 8 + 3] = (uint8_t)(S->h[i] >> 24);
        buffer[i * 8 + 4] = (uint8_t)(S->h[i] >> 32);
        buffer[i * 8 + 5] = (uint8_t)(S->h[i] >> 40);
        buffer[i * 8 + 6] = (uint8_t)(S->h[i] >> 48);
        buffer[i * 8 + 7] = (uint8_t)(S->h[i] >> 56);
    }
    memcpy(out, buffer, S->outlen);
    return 0;
}

int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen) {
    blake2b_state S;
    if (keylen > 0) {
        if (blake2b_init_key(&S, outlen, key, keylen) < 0) return -1;
    } else {
        if (blake2b_init(&S, outlen) < 0) return -1;
    }
    blake2b_update(&S, in, inlen);
    return blake2b_final(&S, out, outlen);
}

int blake2b_long(void *pout, size_t outlen, const void *in, size_t inlen) {
    uint8_t *out = (uint8_t *)pout;
    uint8_t outlen_bytes[4];
    blake2b_state blake_state;

    if (outlen == 0) return -1;

    outlen_bytes[0] = (uint8_t)(outlen & 0xFF);
    outlen_bytes[1] = (uint8_t)((outlen >> 8) & 0xFF);
    outlen_bytes[2] = (uint8_t)((outlen >> 16) & 0xFF);
    outlen_bytes[3] = (uint8_t)((outlen >> 24) & 0xFF);

    if (outlen <= BLAKE2B_OUTBYTES) {
        blake2b_init(&blake_state, outlen);
        blake2b_update(&blake_state, outlen_bytes, 4);
        blake2b_update(&blake_state, in, inlen);
        return blake2b_final(&blake_state, out, outlen);
    } else {
        uint8_t out_buffer[BLAKE2B_OUTBYTES];
        uint8_t in_buffer[BLAKE2B_OUTBYTES];
        size_t toproduce;

        blake2b_init(&blake_state, BLAKE2B_OUTBYTES);
        blake2b_update(&blake_state, outlen_bytes, 4);
        blake2b_update(&blake_state, in, inlen);
        blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES);

        memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
        out += BLAKE2B_OUTBYTES / 2;
        toproduce = outlen - BLAKE2B_OUTBYTES / 2;

        while (toproduce > BLAKE2B_OUTBYTES) {
            memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
            blake2b(out_buffer, BLAKE2B_OUTBYTES, in_buffer, BLAKE2B_OUTBYTES, NULL, 0);
            memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
            out += BLAKE2B_OUTBYTES / 2;
            toproduce -= BLAKE2B_OUTBYTES / 2;
        }

        memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
        blake2b(out_buffer, toproduce, in_buffer, BLAKE2B_OUTBYTES, NULL, 0);
        memcpy(out, out_buffer, toproduce);
        return 0;
    }
}
