#ifndef BLAKE2_H
#define BLAKE2_H

#include <stdint.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES   = 64,
    BLAKE2B_KEYBYTES   = 64,
    BLAKE2B_SALTBYTES  = 16,
    BLAKE2B_PERSONALBYTES = 16
};

#pragma pack(push, 1)
typedef struct blake2b_param__ {
    uint8_t  digest_length;
    uint8_t  key_length;
    uint8_t  fanout;
    uint8_t  depth;
    uint32_t leaf_length;
    uint32_t node_offset;
    uint32_t xof_length;
    uint8_t  node_depth;
    uint8_t  inner_length;
    uint8_t  reserved[14];
    uint8_t  salt[BLAKE2B_SALTBYTES];
    uint8_t  personal[BLAKE2B_PERSONALBYTES];
} blake2b_param;
#pragma pack(pop)

typedef struct blake2b_state__ {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
} blake2b_state;

int blake2b_init(blake2b_state *S, size_t outlen);
int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen);
int blake2b_init_param(blake2b_state *S, const blake2b_param *P);
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final(blake2b_state *S, void *out, size_t outlen);
int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
int blake2b_long(void *out, size_t outlen, const void *in, size_t inlen);

#if defined(__cplusplus)
}
#endif

#endif
