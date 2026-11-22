#ifndef ARGON2_CORE_H
#define ARGON2_CORE_H

#include "argon2.h"
#include "blake2.h"
#include <stdint.h>
#include <stddef.h>

#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_QWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 8)
#define ARGON2_OWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 16)
#define ARGON2_HWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 32)
#define ARGON2_512BIT_WORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 64)

#define ARGON2_PREHASH_DIGEST_LENGTH 64
#define ARGON2_PREHASH_SEED_LENGTH 72

typedef struct block_ {
    uint64_t v[ARGON2_QWORDS_IN_BLOCK];
} block;

typedef struct Argon2_instance_t {
    block *memory;
    uint32_t version;
    uint32_t passes;
    uint32_t memory_blocks;
    uint32_t segment_length;
    uint32_t lane_length;
    uint32_t lanes;
    uint32_t threads;
    argon2_type type;
    int print_internals;
    void *context_ptr;
} argon2_instance_t;

typedef struct Argon2_position_t {
    uint32_t pass;
    uint32_t lane;
    uint8_t slice;
    uint32_t index;
} argon2_position_t;

void init_block_value(block *b, uint8_t in);
void copy_block(block *dst, const block *src);
void xor_block(block *dst, const block *src);
void fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance);
void initial_hash(uint8_t *blockhash, argon2_type type, uint32_t version,
                  uint32_t lanes, uint32_t outlen, uint32_t m_cost,
                  uint32_t t_cost, const void *pwd, size_t pwdlen,
                  const void *salt, size_t saltlen, const void *secret,
                  size_t secretlen, const void *ad, size_t adlen);
int validate_inputs(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                    const void *pwd, size_t pwdlen, const void *salt,
                    size_t saltlen, const void *hash, size_t hashlen);
int fill_memory_blocks(argon2_instance_t *instance);

#endif
