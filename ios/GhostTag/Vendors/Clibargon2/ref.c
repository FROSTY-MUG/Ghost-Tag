#include "core.h"
#include <string.h>

static inline uint64_t rotr64(const uint64_t w, const unsigned c) {
    return (w >> c) | (w << (64 - c));
}

static inline uint64_t f_mul(uint64_t x, uint64_t y) {
    return (uint64_t)(uint32_t)x * (uint64_t)(uint32_t)y;
}

#define G(a, b, c, d) \
    do { \
        a = a + b + 2 * f_mul(a, b); \
        d = rotr64(d ^ a, 32); \
        c = c + d + 2 * f_mul(c, d); \
        b = rotr64(b ^ c, 24); \
        a = a + b + 2 * f_mul(a, b); \
        d = rotr64(d ^ a, 16); \
        c = c + d + 2 * f_mul(c, d); \
        b = rotr64(b ^ c, 63); \
    } while (0)

static void apply_permutation(block *state) {
    uint64_t *v = state->v;
    /* Columns */
    for (int i = 0; i < 8; ++i) {
        G(v[i], v[i + 8], v[i + 16], v[i + 24]);
        G(v[i + 32], v[i + 40], v[i + 48], v[i + 56]);
        G(v[i + 64], v[i + 72], v[i + 80], v[i + 88]);
        G(v[i + 96], v[i + 104], v[i + 112], v[i + 120]);
    }
    /* Rows */
    for (int i = 0; i < 16; i += 2) {
        G(v[i * 8], v[i * 8 + 1], v[i * 8 + 2], v[i * 8 + 3]);
        G(v[i * 8 + 4], v[i * 8 + 5], v[i * 8 + 6], v[i * 8 + 7]);
        G(v[(i + 1) * 8], v[(i + 1) * 8 + 1], v[(i + 1) * 8 + 2], v[(i + 1) * 8 + 3]);
        G(v[(i + 1) * 8 + 4], v[(i + 1) * 8 + 5], v[(i + 1) * 8 + 6], v[(i + 1) * 8 + 7]);
    }
}

static void fill_block(const block *prev_block, const block *ref_block,
                       block *next_block, int with_xor) {
    block blockR;
    copy_block(&blockR, prev_block);
    xor_block(&blockR, ref_block);
    block block_tmp;
    copy_block(&block_tmp, &blockR);

    /* 2x2 permutation matrix on 1024-byte block */
    uint64_t *v = block_tmp.v;
    for (int i = 0; i < 8; ++i) {
        G(v[16 * i + 0], v[16 * i + 4], v[16 * i + 8], v[16 * i + 12]);
        G(v[16 * i + 1], v[16 * i + 5], v[16 * i + 9], v[16 * i + 13]);
        G(v[16 * i + 2], v[16 * i + 6], v[16 * i + 10], v[16 * i + 14]);
        G(v[16 * i + 3], v[16 * i + 7], v[16 * i + 11], v[16 * i + 15]);

        G(v[16 * i + 0], v[16 * i + 5], v[16 * i + 10], v[16 * i + 15]);
        G(v[16 * i + 1], v[16 * i + 6], v[16 * i + 11], v[16 * i + 12]);
        G(v[16 * i + 2], v[16 * i + 7], v[16 * i + 8], v[16 * i + 13]);
        G(v[16 * i + 3], v[16 * i + 4], v[16 * i + 9], v[16 * i + 14]);
    }

    for (int i = 0; i < 8; ++i) {
        G(v[2 * i + 0], v[2 * i + 16], v[2 * i + 32], v[2 * i + 48]);
        G(v[2 * i + 1], v[2 * i + 17], v[2 * i + 33], v[2 * i + 49]);
        G(v[2 * i + 64], v[2 * i + 80], v[2 * i + 96], v[2 * i + 112]);
        G(v[2 * i + 65], v[2 * i + 81], v[2 * i + 97], v[2 * i + 113]);

        G(v[2 * i + 0], v[2 * i + 17], v[2 * i + 96], v[2 * i + 113]);
        G(v[2 * i + 1], v[2 * i + 80], v[2 * i + 97], v[2 * i + 48]);
        G(v[2 * i + 64], v[2 * i + 81], v[2 * i + 32], v[2 * i + 49]);
        G(v[2 * i + 65], v[2 * i + 16], v[2 * i + 33], v[2 * i + 112]);
    }

    if (with_xor) {
        xor_block(&block_tmp, &blockR);
        xor_block(next_block, &block_tmp);
    } else {
        xor_block(&block_tmp, &blockR);
        copy_block(next_block, &block_tmp);
    }
}

static uint32_t index_alpha(const argon2_instance_t *instance,
                            const argon2_position_t *position, uint32_t pseudo_rand,
                            int same_lane) {
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position;

    if (position->pass == 0) {
        if (position->slice == 0) {
            reference_area_size = position->index - 1;
        } else {
            if (same_lane) {
                reference_area_size = position->slice * instance->segment_length + position->index - 1;
            } else {
                reference_area_size = position->slice * instance->segment_length + ((position->index == 0) ? -1 : 0);
            }
        }
    } else {
        if (same_lane) {
            reference_area_size = instance->lane_length - instance->segment_length + position->index - 1;
        } else {
            reference_area_size = instance->lane_length - instance->segment_length + ((position->index == 0) ? -1 : 0);
        }
    }

    uint64_t pseudo_rand64 = pseudo_rand;
    uint64_t x = (pseudo_rand64 * pseudo_rand64) >> 32;
    uint64_t y = ((uint64_t)reference_area_size * x) >> 32;
    relative_position = (uint64_t)reference_area_size - 1 - y;

    if (position->pass != 0) {
        start_position = (position->slice == 3) ? 0 : (position->slice + 1) * instance->segment_length;
    } else {
        start_position = 0;
    }

    return (uint32_t)((start_position + relative_position) % instance->lane_length);
}

static void fill_segment(const argon2_instance_t *instance,
                         argon2_position_t position) {
    block address_block, input_block;
    int data_independent_addressing = (instance->type == Argon2_i) ||
        (instance->type == Argon2_id && (position.pass == 0) && (position.slice < 2));

    if (data_independent_addressing) {
        init_block_value(&input_block, 0);
        input_block.v[0] = position.pass;
        input_block.v[1] = position.lane;
        input_block.v[2] = position.slice;
        input_block.v[3] = instance->memory_blocks;
        input_block.v[4] = instance->passes;
        input_block.v[5] = instance->type;
    }

    uint32_t starting_index = (position.pass == 0 && position.slice == 0) ? 2 : 0;
    uint32_t curr_offset = position.lane * instance->lane_length +
                           position.slice * instance->segment_length + starting_index;
    uint32_t prev_offset = (curr_offset % instance->lane_length == 0) ?
                           curr_offset + instance->lane_length - 1 : curr_offset - 1;

    for (position.index = starting_index; position.index < instance->segment_length;
         ++position.index, ++curr_offset, ++prev_offset) {
        if (curr_offset % instance->lane_length == 1) {
            prev_offset = curr_offset - 1;
        }

        uint64_t pseudo_rand;
        if (data_independent_addressing) {
            if (position.index % ARGON2_QWORDS_IN_BLOCK == 0) {
                input_block.v[6]++;
                init_block_value(&address_block, 0);
                fill_block(&input_block, &address_block, &address_block, 0);
                fill_block(&address_block, &address_block, &address_block, 0);
            }
            pseudo_rand = address_block.v[position.index % ARGON2_QWORDS_IN_BLOCK];
        } else {
            pseudo_rand = instance->memory[prev_offset].v[0];
        }

        uint32_t ref_lane = ((position.pass == 0) && (position.slice == 0)) ?
                            position.lane :
                            (uint32_t)(((pseudo_rand >> 32) % instance->lanes));

        uint32_t ref_index = index_alpha(instance, &position, (uint32_t)pseudo_rand,
                                         ref_lane == position.lane);

        block *prev = &instance->memory[prev_offset];
        block *ref = &instance->memory[ref_lane * instance->lane_length + ref_index];
        block *curr = &instance->memory[curr_offset];

        fill_block(prev, ref, curr, position.pass != 0);
    }
}

int fill_memory_blocks(argon2_instance_t *instance) {
    argon2_position_t position;
    for (uint32_t pass = 0; pass < instance->passes; ++pass) {
        for (uint8_t slice = 0; slice < ARGON2_SYNC_POINTS; ++slice) {
            for (uint32_t lane = 0; lane < instance->lanes; ++lane) {
                position.pass = pass;
                position.slice = slice;
                position.lane = lane;
                position.index = 0;
                fill_segment(instance, position);
            }
        }
    }
    return ARGON2_OK;
}
