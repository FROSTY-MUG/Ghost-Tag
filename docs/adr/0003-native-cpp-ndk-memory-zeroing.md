# ADR 0003: Native C++ NDK for Volatile Memory Zeroization

## Status
**Accepted** (2026-11-13)

## Context
In garbage-collected runtimes like JavaScript (V8 / Hermes) and JVM / Android ART, strings and arrays are immutable or subject to runtime memory compaction. 
Standard loops writing zeros can be eliminated as "dead stores" by optimizing compilers, leaving cryptographic keys lingering in process memory until garbage collected.

## Decision
We introduce a native C++ JNI module (`android/app/src/main/cpp/ghosttag_native_security.cpp`) compiled with the Android NDK:
- Direct access to direct byte buffers outside the garbage-collected heap.
- Wipes sensitive key material using `memset_s` or volatile 4-pass overwrites (`0x00`, `0xFF`, `0xAA`, `0x00`) to guarantee compiler dead-store elimination does not occur.
- Implements `CRYPTO_memcmp` constant-time buffer comparisons to protect against timing attacks.

## Consequences
### Positive
- True memory zeroization of passphrases and DEKs immediately after cryptographic operations.
- Protection against heap inspection and post-mortem memory dumps.
- Deterministic constant-time verification of authentication tags.

### Negative
- Requires Android NDK and CMake build toolchain.
- Platform-specific native build configuration.
