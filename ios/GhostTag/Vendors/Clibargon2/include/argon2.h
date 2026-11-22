#ifndef ARGON2_H
#define ARGON2_H

#include <stdint.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define ARGON2_VERSION_10 0x10
#define ARGON2_VERSION_13 0x13
#define ARGON2_VERSION_NUMBER ARGON2_VERSION_13

#define ARGON2_MIN_LANES 1
#define ARGON2_MAX_LANES 0xFFFFFF
#define ARGON2_MIN_THREADS 1
#define ARGON2_MAX_THREADS 0xFFFFFF
#define ARGON2_SYNC_POINTS 4
#define ARGON2_MIN_OUTLEN 4
#define ARGON2_MAX_OUTLEN 0xFFFFFFFF
#define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS)
#define ARGON2_MIN_TIME 1
#define ARGON2_MAX_TIME 0xFFFFFFFF
#define ARGON2_MIN_PWD_LENGTH 0
#define ARGON2_MAX_PWD_LENGTH 0xFFFFFFFF
#define ARGON2_MIN_SALT_LENGTH 8
#define ARGON2_MAX_SALT_LENGTH 0xFFFFFFFF
#define ARGON2_MIN_SECRET 0
#define ARGON2_MAX_SECRET 0xFFFFFFFF
#define ARGON2_MIN_AD_LENGTH 0
#define ARGON2_MAX_AD_LENGTH 0xFFFFFFFF

typedef enum Argon2_type {
    Argon2_d = 0,
    Argon2_i = 1,
    Argon2_id = 2
} argon2_type;

typedef enum Argon2_error_codes {
    ARGON2_OK = 0,
    ARGON2_OUTPUT_PTR_NULL = 1,
    ARGON2_OUTPUT_TOO_SHORT = 2,
    ARGON2_OUTPUT_TOO_LONG = 3,
    ARGON2_PWD_TOO_SHORT = 4,
    ARGON2_PWD_TOO_LONG = 5,
    ARGON2_SALT_TOO_SHORT = 6,
    ARGON2_SALT_TOO_LONG = 7,
    ARGON2_AD_TOO_SHORT = 8,
    ARGON2_AD_TOO_LONG = 9,
    ARGON2_SECRET_TOO_SHORT = 10,
    ARGON2_SECRET_TOO_LONG = 11,
    ARGON2_TIME_TOO_SMALL = 12,
    ARGON2_TIME_TOO_LARGE = 13,
    ARGON2_MEMORY_TOO_LITTLE = 14,
    ARGON2_MEMORY_TOO_MUCH = 15,
    ARGON2_LANES_TOO_FEW = 16,
    ARGON2_LANES_TOO_MANY = 17,
    ARGON2_PWD_PTR_MISMATCH = 18,
    ARGON2_SALT_PTR_MISMATCH = 19,
    ARGON2_SECRET_PTR_MISMATCH = 20,
    ARGON2_AD_PTR_MISMATCH = 21,
    ARGON2_MEMORY_ALLOCATION_ERROR = 22,
    ARGON2_FREE_MEMORY_CBK_NULL = 23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = 24,
    ARGON2_INCORRECT_PARAMETER = 25,
    ARGON2_INCORRECT_TYPE = 26,
    ARGON2_OUT_PTR_MISMATCH = 27,
    ARGON2_THREADS_TOO_FEW = 28,
    ARGON2_THREADS_TOO_MANY = 29,
    ARGON2_MISSING_ARGS = 30,
    ARGON2_ENCODING_FAIL = 31,
    ARGON2_DECODING_FAIL = 32,
    ARGON2_THREAD_FAIL = 33,
    ARGON2_DECODING_LENGTH_FAIL = 34,
    ARGON2_VERIFY_MISMATCH = 35
} argon2_error_codes;

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash, const size_t hashlen);

int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
                const uint32_t parallelism, const void *pwd,
                const size_t pwdlen, const void *salt, const size_t saltlen,
                void *hash, const size_t hashlen, char *encoded,
                const size_t encodedlen, argon2_type type,
                const uint32_t version);

const char *argon2_error_message(int error_code);

#if defined(__cplusplus)
}
#endif

#endif
