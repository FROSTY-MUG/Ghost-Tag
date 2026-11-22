#include "core.h"
#include <stdlib.h>
#include <string.h>

void init_block_value(block *b, uint8_t in) {
    memset(b->v, in, sizeof(b->v));
}

void copy_block(block *dst, const block *src) {
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}

void xor_block(block *dst, const block *src) {
    for (size_t i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] ^= src->v[i];
    }
}

static void store32(uint8_t *dst, uint32_t w) {
    dst[0] = (uint8_t)(w >> 0);
    dst[1] = (uint8_t)(w >> 8);
    dst[2] = (uint8_t)(w >> 16);
    dst[3] = (uint8_t)(w >> 24);
}

void initial_hash(uint8_t *blockhash, argon2_type type, uint32_t version,
                  uint32_t lanes, uint32_t outlen, uint32_t m_cost,
                  uint32_t t_cost, const void *pwd, size_t pwdlen,
                  const void *salt, size_t saltlen, const void *secret,
                  size_t secretlen, const void *ad, size_t adlen) {
    blake2b_state state;
    uint8_t value[4];

    blake2b_init(&state, ARGON2_PREHASH_DIGEST_LENGTH);

    store32(value, lanes);
    blake2b_update(&state, value, 4);

    store32(value, outlen);
    blake2b_update(&state, value, 4);

    store32(value, m_cost);
    blake2b_update(&state, value, 4);

    store32(value, t_cost);
    blake2b_update(&state, value, 4);

    store32(value, version);
    blake2b_update(&state, value, 4);

    store32(value, (uint32_t)type);
    blake2b_update(&state, value, 4);

    store32(value, (uint32_t)pwdlen);
    blake2b_update(&state, value, 4);
    if (pwd != NULL) blake2b_update(&state, pwd, pwdlen);

    store32(value, (uint32_t)saltlen);
    blake2b_update(&state, value, 4);
    if (salt != NULL) blake2b_update(&state, salt, saltlen);

    store32(value, (uint32_t)secretlen);
    blake2b_update(&state, value, 4);
    if (secret != NULL) blake2b_update(&state, secret, secretlen);

    store32(value, (uint32_t)adlen);
    blake2b_update(&state, value, 4);
    if (ad != NULL) blake2b_update(&state, ad, adlen);

    blake2b_final(&state, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

void fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance) {
    for (uint32_t l = 0; l < instance->lanes; ++l) {
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        blake2b_long((uint8_t *)(instance->memory + l * instance->lane_length + 0),
                     ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);

        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        blake2b_long((uint8_t *)(instance->memory + l * instance->lane_length + 1),
                     ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
    }
}

int validate_inputs(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                    const void *pwd, size_t pwdlen, const void *salt,
                    size_t saltlen, const void *hash, size_t hashlen) {
    if (pwdlen < ARGON2_MIN_PWD_LENGTH || pwdlen > ARGON2_MAX_PWD_LENGTH)
        return ARGON2_PWD_TOO_SHORT;
    if (pwd == NULL && pwdlen > 0) return ARGON2_PWD_PTR_MISMATCH;
    if (saltlen < ARGON2_MIN_SALT_LENGTH || saltlen > ARGON2_MAX_SALT_LENGTH)
        return ARGON2_SALT_TOO_SHORT;
    if (salt == NULL) return ARGON2_SALT_PTR_MISMATCH;
    if (hashlen < ARGON2_MIN_OUTLEN || hashlen > ARGON2_MAX_OUTLEN)
        return ARGON2_OUTPUT_TOO_SHORT;
    if (hash == NULL) return ARGON2_OUTPUT_PTR_NULL;
    if (t_cost < ARGON2_MIN_TIME || t_cost > ARGON2_MAX_TIME)
        return ARGON2_TIME_TOO_SMALL;
    if (m_cost < 8 * parallelism)
        return ARGON2_MEMORY_TOO_LITTLE;
    if (parallelism < ARGON2_MIN_LANES || parallelism > ARGON2_MAX_LANES)
        return ARGON2_LANES_TOO_FEW;
    return ARGON2_OK;
}
