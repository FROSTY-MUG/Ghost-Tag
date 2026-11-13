/**
 * @file secure_memory.h
 * @summary Native Secure Memory Scrubbing and Page Locking.
 *
 * Implements non-optimizable memory zeroization, memory page locking (mlock),
 * and constant-time memory comparison to protect sensitive cryptographic buffers
 * (passphrase hashes, KEKs, DEKs) from paging out to swap, cold-boot attacks,
 * or heap inspection.
 */

#ifndef GHOSTTAG_SECURE_MEMORY_H
#define GHOSTTAG_SECURE_MEMORY_H

#include <cstddef>

namespace ghosttag {

class SecureMemory {
public:
    /**
     * Locks the given memory range into physical RAM using mlock().
     * Prevents the OS kernel from paging sensitive key material to disk/swap.
     */
    static bool lockMemory(void* addr, size_t len);

    /**
     * Unlocks previously locked memory range using munlock().
     */
    static bool unlockMemory(void* addr, size_t len);

    /**
     * Multi-pass volatile zeroization with compiler clobber barriers.
     * Guaranteed not to be removed by compiler dead-store elimination.
     */
    static void wipeBuffer(void* addr, size_t len);

    /**
     * Constant-time memory comparison to prevent timing side channels.
     * @return 0 if buffers are identical, non-zero otherwise.
     */
    static int timingSafeCompare(const void* a, const void* b, size_t len);
};

} // namespace ghosttag

#endif // GHOSTTAG_SECURE_MEMORY_H
