/**
 * @file secure_memory.cpp
 * @summary Native Secure Memory Scrubbing and Page Locking Implementation.
 */

#include "secure_memory.h"

#include <sys/mman.h>
#include <cstring>

namespace ghosttag {

bool SecureMemory::lockMemory(void* addr, size_t len) {
    if (!addr || len == 0) {
        return false;
    }
    return (mlock(addr, len) == 0);
}

bool SecureMemory::unlockMemory(void* addr, size_t len) {
    if (!addr || len == 0) {
        return false;
    }
    return (munlock(addr, len) == 0);
}

void SecureMemory::wipeBuffer(void* addr, size_t len) {
    if (!addr || len == 0) {
        return;
    }

    volatile unsigned char* p = static_cast<volatile unsigned char*>(addr);

    // Pass 1: 0xAA (10101010)
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0xAA;
    }
    // Memory clobber barrier: prevents compiler optimization
    asm volatile("" : : "r"(addr) : "memory");

    // Pass 2: 0x55 (01010101)
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0x55;
    }
    asm volatile("" : : "r"(addr) : "memory");

    // Pass 3: Complete zeroization 0x00
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0x00;
    }
    asm volatile("" : : "r"(addr) : "memory");
}

int SecureMemory::timingSafeCompare(const void* a, const void* b, size_t len) {
    const unsigned char* ua = static_cast<const unsigned char*>(a);
    const unsigned char* ub = static_cast<const unsigned char*>(b);
    unsigned char result = 0;

    for (size_t i = 0; i < len; ++i) {
        result |= (ua[i] ^ ub[i]);
    }

    return (result != 0);
}

} // namespace ghosttag

