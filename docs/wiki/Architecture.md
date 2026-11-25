# Architecture

Ghost-Tag enforces strict unidirectional layering so cryptographic primitives, binary wire formats, and finite-state workflows operate identically offline across mobile, web, and desktop bridges.

## Layering Model
1. **Contracts (`src/contracts/`)**: Zero-dependency Little-Endian envelope layouts (`54B` `v1`, `134B` `v2`), NTAG21x memory profiles (`TAG_CAPACITIES`), KDF tiers (`DEFAULT_KDF_PARAMETERS_BY_TIER`), typed error enums, and FSM state enums.
2. **Cryptographic & Domain Core (`src/crypto/`, `src/vault/`, `src/security/`, `src/nfc/`)**: RFC 9106 Argon2id (`16/32/64 MiB` primary tiers), AES-256-GCM (`12B` nonce, `16B` tag), Cauchy-Vandermonde Reed-Solomon over $\mathrm{GF}(2^8)$, NIST-aligned key wrapping (`19B` AAD), volatile 72h `ChunkCacheManager`, and `4`-pass volatile buffer wiping.
3. **Operations Engine (`src/operations/`)**: Coordinates Scan, Write, BulkWrite, BulkScan, Reconstruction, and Wipe flows strictly via real hardware managers (no synthetic `setTimeout` fallbacks).
4. **Native & Companion Surfaces**: Android Kotlin + C++17 NDK (`mlock()`, `ptrace`, `/proc/self/maps`, `FLAG_SECURE`), Vite Web Companion + `hash-wasm` Argon2id WASM, and Desktop Ghost Bridge (`127.0.0.1:41789` PC/SC + PN532).

## Canonical Documentation
- [System Architecture (`docs/architecture.md`)](../architecture.md)
- [Canonical Specification (`docs/CANONICAL-SPECIFICATION.md`)](../CANONICAL-SPECIFICATION.md)
- [Annotated File Tree (`docs/code-structure.md`)](../code-structure.md)
