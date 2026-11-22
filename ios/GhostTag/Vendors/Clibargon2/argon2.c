#include "argon2.h"
#include "core.h"
#include <stdlib.h>
#include <string.h>

const char *argon2_error_message(int error_code) {
    switch (error_code) {
    case ARGON2_OK: return "OK";
    case ARGON2_OUTPUT_PTR_NULL: return "Output pointer is NULL";
    case ARGON2_OUTPUT_TOO_SHORT: return "Output is too short";
    case ARGON2_OUTPUT_TOO_LONG: return "Output is too long";
    case ARGON2_PWD_TOO_SHORT: return "Password is too short";
    case ARGON2_PWD_TOO_LONG: return "Password is too long";
    case ARGON2_SALT_TOO_SHORT: return "Salt is too short";
    case ARGON2_SALT_TOO_LONG: return "Salt is too long";
    case ARGON2_TIME_TOO_SMALL: return "Time cost is too small";
    case ARGON2_MEMORY_TOO_LITTLE: return "Memory cost is too small";
    case ARGON2_LANES_TOO_FEW: return "Too few lanes";
    case ARGON2_MEMORY_ALLOCATION_ERROR: return "Memory allocation failed";
    default: return "Unknown error";
    }
}

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash, const size_t hashlen) {
    int result = validate_inputs(t_cost, m_cost, parallelism, pwd, pwdlen,
                                 salt, saltlen, hash, hashlen);
    if (result != ARGON2_OK) return result;

    uint32_t memory_blocks = m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * parallelism) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * parallelism;
    }
    uint32_t segment_length = memory_blocks / (parallelism * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (parallelism * ARGON2_SYNC_POINTS);

    argon2_instance_t instance;
    instance.version = ARGON2_VERSION_NUMBER;
    instance.passes = t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = parallelism;
    instance.threads = parallelism;
    instance.type = Argon2_id;
    instance.print_internals = 0;

    instance.memory = (block *)calloc(memory_blocks, sizeof(block));
    if (instance.memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    initial_hash(blockhash, instance.type, instance.version, instance.lanes,
                 (uint32_t)hashlen, m_cost, t_cost, pwd, pwdlen,
                 salt, saltlen, NULL, 0, NULL, 0);

    fill_first_blocks(blockhash, &instance);

    result = fill_memory_blocks(&instance);
    if (result != ARGON2_OK) {
        free(instance.memory);
        return result;
    }

    /* Compute final block XOR sum across all lanes */
    block final_block;
    copy_block(&final_block, &instance.memory[instance.lane_length - 1]);
    for (uint32_t l = 1; l < instance.lanes; ++l) {
        xor_block(&final_block, &instance.memory[l * instance.lane_length + instance.lane_length - 1]);
    }

    blake2b_long((uint8_t *)hash, hashlen, (const uint8_t *)&final_block, sizeof(block));

    /* Wipe memory safely */
    memset(instance.memory, 0, sizeof(block) * memory_blocks);
    memset(&final_block, 0, sizeof(block));
    memset(blockhash, 0, sizeof(blockhash));
    free(instance.memory);

    return ARGON2_OK;
}
