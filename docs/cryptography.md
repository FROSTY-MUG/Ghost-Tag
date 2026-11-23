# Ghost-Tag Cryptographic Core Specification

> [!NOTE]
> **CANONICAL SPECIFICATION ALIGNMENT**  
> For the authoritative wire layouts, cryptographic parameters, envelope definitions, and cross-platform derivation standards, refer to [CANONICAL-SPECIFICATION.md](file:///c:/Users/Aryan/Desktop/Projects/Ghost-Tag/docs/CANONICAL-SPECIFICATION.md).
> 
> Key Invariants:
> - **Canonical Recovery**: 12-word BIP-39 English mnemonic across Android, Web, and iOS.
> - **Bulk Envelope**: Exact 134-byte fixed overhead with MAGIC `GTAG` (0x47, 0x54, 0x41, 0x47), FORMAT_VERSION `0x02`, RECORD_TYPE `0x10`, 74-byte deterministic AAD (ending at byte 73), and a full **32-byte SHA-256 chunk hash** at bytes 74..105.
> - **Chunk Cache**: Strictly in volatile RAM (`Map`) with 72-hour TTL timer; zero disk writes.

Ghost-Tag employs authenticated symmetric encryption coupled with a memory-hard key derivation function to guarantee confidentiality, authenticity, and recoverability.

---

## 1. Key Hierarchy Architecture

Ghost-Tag explicitly avoids using a single master symmetric key for all operations. Instead, it utilizes a two-tier cryptographic key hierarchy:

```
                  +----------------------------------+
                  |         User Passphrase          |
                  |     (>= 16 characters, secret)   |
                  +-----------------+----------------+
                                    |
                                    v
                     Argon2id(passphrase, salt, params)
                                    |
                                    v
                  +----------------------------------+
                  |    Key-Encryption Key (KEK)      |
                  |  (256-bit AES key, ephemeral)    |
                  +-------+------------------+-------+
                          |                  |
                          v                  v
                   AES-256-GCM Wrap   AES-256-GCM Wrap
                          |                  |
                          v                  v
                  +---------------+  +---------------+
                  | Wrapped DEK 1 |  | Wrapped DEK 2 |  (Stored at rest in Vault)
                  +-------+-------+  +---------------+
                          | (Unwrapped into memory per session)
                          v
                  +---------------+
                  | Raw DEK (32B) |
                  +-------+-------+
                          |
                          v
                  AES-256-GCM Encrypt(Payload, AAD)
                          |
                          v
                  +----------------------------------+
                  |     Encrypted NFC Tag Envelope   |
                  +----------------------------------+
```

---

## 2. Key Derivation: Argon2id (RFC 9106)

To derive the 256-bit Key Encryption Key (KEK) from the user master passphrase, Ghost-Tag executes Argon2id, the state-of-the-art memory-hard password hashing function.

### Properties:
- **Salt**: 16 bytes (128 bits) generated via cryptographically secure random number generator (CSPRNG).
- **Output Length**: 32 bytes (256 bits).
- **Algorithm Variant**: Argon2id (`v=0x13`), balancing side-channel resistance with brute-force defense against GPU/ASIC adversaries.

### Device-Calibrated Work Factor Profiles:

| Device Tier | Memory Cost ($m$) | Time Cost ($t$) | Parallelism ($p$) | Target Latency |
| :--- | :--- | :--- | :--- | :--- |
| **High-End Android** | 64 MiB ($65,536$ KiB) | 3 iterations | 4 lanes | 500 – 1,000 ms |
| **Standard Android** | 32 MiB ($32,768$ KiB) | 3 iterations | 2 lanes | 500 – 1,000 ms |
| **Low-End Android** | 16 MiB ($16,384$ KiB) | 2 iterations | 1 lane | 1,000 – 2,000 ms |

Ghost-Tag benchmarks host CPU/memory speed during initial onboarding and persists the selected parameters. Subsequent vault unlocks mandate that the stored parameters are used; **parameter downgrades are strictly rejected**.

---

## 3. Key Wrapping Specification

Data Encryption Keys (DEKs) are generated as unique 256-bit random vectors per tag or vault entry. They are **never persisted in plaintext**.

Wrapping is performed using AES-256-GCM:
$$\text{WrappedDEK} = \text{AES-256-GCM}_{\text{KEK}}(\text{IV} = \text{random 12B}, \text{Plaintext} = \text{DEK}, \text{AAD} = \text{KeyWrapAAD})$$

### Key Wrap AAD:
$$\text{KeyWrapAAD} = \text{0x57} \;(\text{ASCII 'W'}) \;||\; \text{KEY\_ID (16B)} \;||\; \text{KDF\_VERSION (2B Little-Endian)}$$

This binds the wrapped key to its explicit identifier and schema version, preventing ciphertext substitution or cut-and-paste key transplantation attacks across vault entries.

---

## 4. Authenticated Payload Encryption: AES-256-GCM

Payloads written to NFC tags are encrypted using AES-256 in Galois/Counter Mode (GCM).

### Invariants:
- **Cipher**: AES-256-GCM (`aes-256-gcm`).
- **Initialization Vector (Nonce)**: Fresh 12-byte (96-bit) CSPRNG random nonce per write operation. Nonces are never repeated.
- **Authentication Tag**: 16 bytes (128 bits) computed over both ciphertext and Additional Authenticated Data (AAD).
- **Constant Time**: Decryption verifies the tag in constant time. Any bit flip in the ciphertext, nonce, or metadata causes tag verification to abort with `GCM_AUTH_FAILED`.

### Additional Authenticated Data (AAD):
$$\text{AAD} = \text{"GTAG"} \;||\; \text{FORMAT\_VERSION (1B)} \;||\; \text{PURPOSE (1B)} \;||\; \text{KEY\_ID (16B)} \;||\; \text{CIPHERTEXT\_LENGTH (4B LE)}$$

Total AAD length is precisely **26 bytes**. Binding header fields ensures an adversary cannot:
1. Re-label a `CREDENTIAL` payload as a `NOTE`.
2. Swap ciphertext between different keys without detection.
3. Truncate or pad ciphertext without invalidating the authentication tag.

---

## 5. Recovery Hierarchy

To ensure recoverability when a device is lost or replaced:

```
               +--------------------------------------+
               |          256-bit Recovery Secret     |
               |      (Presented as 24 BIP39 Words)   |
               +------------------+-------------------+
                                  |
                                  v
              Argon2id(secret, dedicated_32B_salt, recovery_params)
                                  |
                                  v
               +--------------------------------------+
               |            Recovery KEK              |
               +------------------+-------------------+
                                  |
                                  v
                     AES-256-GCM Recovery Wrapped DEKs
```

- **Mnemonic Encoding**: Canonical 12-word BIP-39 English mnemonic (128 bits entropy + 4 bits checksum = 132 bits). The underlying engine retains legacy support for 24-word offline envelopes (256 bits entropy + 8 bits checksum).
- **Isolated Parameters**: Uses a dedicated 32-byte salt and independent Argon2id work factors distinct from the primary passphrase KDF.
- **Recovery Envelope**: Stored locally or exported to allow recreating access to tag DEKs if the primary passphrase is lost.

---

## 6. Bulk File Encryption & 74-Byte AAD Specification

For multi-file distributed storage across physical NFC tags (Ghost-Tag Bulk Scanning v2):

### 6.1 Whole-File Encryption:
Prior to chunking, each arbitrary file (opaque binary stream) is encrypted as a single atomic unit using AES-256-GCM under the vault DEK:
$$\text{FullCiphertext} = \text{AES-256-GCM}_{\text{DEK}}(\text{IV} = \text{random 12B}, \text{Plaintext} = \text{FileBytes}, \text{AAD} = \text{FileId (16B)})$$

### 6.2 Chunk Framing & 74-Byte AAD Binding:
The encrypted binary stream is split into $K$ data chunks. Each chunk is framed into a 134-byte binary envelope (`application/vnd.ghost.bulk`) with **74 bytes of Additional Authenticated Data (AAD)**:

$$\begin{aligned}
\text{ChunkAAD} = &\ \text{MAGIC ("GTAG", 4B)} \mathbin{\Vert} \text{FORMAT\_VERSION (0x02, 1B)} \mathbin{\Vert} \text{RECORD\_TYPE (0x10, 1B)} \\
&\mathbin{\Vert} \text{VAULT\_ID (16B)} \mathbin{\Vert} \text{FILE\_ID (16B)} \mathbin{\Vert} \text{KEY\_ID (16B)} \\
&\mathbin{\Vert} \text{GLOBAL\_CHUNK\_INDEX (4B LE)} \mathbin{\Vert} \text{TOTAL\_VAULT\_CHUNKS (4B LE)} \\
&\mathbin{\Vert} \text{FILE\_CHUNK\_INDEX (4B LE)} \mathbin{\Vert} \text{TOTAL\_FILE\_CHUNKS (4B LE)} \\
&\mathbin{\Vert} \text{CHUNK\_CIPHERTEXT\_LENGTH (4B LE)}
\end{aligned}$$

Following the 74-byte AAD header, the envelope stores:
- **`CHUNK_HASH` (32 Bytes)**: Full SHA-256 digest of the chunk ciphertext (bytes `74..105`), acting as an independent pre-authentication integrity gate.
- **`NONCE` (12 Bytes)**: 96-bit AES-256-GCM IV (bytes `106..117`).
- **`CHUNK_CIPHERTEXT` ($N$ Bytes)**: AES-256-GCM ciphertext (bytes `118..117+N`).
- **`GCM_TAG` (16 Bytes)**: 128-bit authentication tag protecting the 74-byte AAD and ciphertext.

Binding all 74 bytes of topological and identity metadata guarantees that an attacker cannot:
1. Replay a chunk from Vault A into Vault B.
2. Swap chunks between different positions or files.
3. Alter payload length without invalidating the 128-bit authentication tag.

---

## 7. Cauchy-Vandermonde Reed-Solomon Erasure Coding ($\text{GF}(2^8)$)

Ghost-Tag Bulk Scanning v2 implements Cauchy-Vandermonde erasure coding over the finite Galois Field $\text{GF}(2^8)$ defined by the irreducible generator polynomial:
$$P(x) = x^8 + x^4 + x^3 + x^2 + 1 \quad (\text{0x11D})$$

### 7.1 Encoding:
Given $K$ data chunks and $M$ parity/recovery chunks:
- A Cauchy generator matrix $\mathbf{C} \in \text{GF}(2^8)^{(K+M) \times K}$ is constructed:
$$C_{i,j} = \frac{1}{X_i \oplus Y_j}$$
where $X = \{0, 1, \dots, K+M-1\}$ and $Y = \{K+M, K+M+1, \dots, 2K+M-1\}$ are disjoint sets in $\text{GF}(2^8)$.
- The first $K$ rows form the systematic identity matrix $\mathbf{I}_K$.
- The lower $M$ rows compute the parity chunks:
$$\mathbf{P} = \mathbf{C}_{\text{parity}} \cdot \mathbf{D}$$

### 7.2 Fault Tolerance & Reconstruction:
- **Maximum Distance Separable (MDS) Property**: Any $K$ distinct chunks out of the $K + M$ total chunks are mathematically sufficient to reconstruct the entire file.
- Even if up to $M$ physical NFC tags are permanently lost, broken, or stolen, Ghost-Tag solves the linear system $\mathbf{C}_{\text{sub}} \cdot \mathbf{D} = \mathbf{Chunks}_{\text{received}}$ via Gaussian elimination over $\text{GF}(2^8)$ to fully recover the original ciphertext.

---

## 8. Memory Protection, Page Locking & Volatile Scrubbing

Ghost-Tag enforces hardware and kernel-level memory defense:

1. **Kernel Page Locking (`mlock`)**:
   - In the native C++ layer (`libghosttag_security.so`), key and passphrase buffers are locked into physical RAM via `mlock()`.
   - The Linux kernel is forbidden from paging or swapping these memory pages out to flash storage or zRAM, eliminating permanent storage remanence across reboots.

2. **4-Pass Volatile Memory Scrubbing**:
   - To defeat compiler dead-store elimination (where Clang/LLVM removes zeroing code if a buffer is about to be deallocated):
     - **Pass 1**: Fill buffer with alternating bit pattern `0xAA` (`10101010`).
     - **Memory Barrier**: `asm volatile("" : : "r"(addr) : "memory")` forces the compiler to execute the stores.
     - **Pass 2**: Fill buffer with inverted bit pattern `0x55` (`01010101`).
     - **Memory Barrier**: Second clobber barrier.
     - **Pass 3**: Fill buffer with cryptographically secure random bytes.
     - **Pass 4**: Complete zeroization `0x00`.

3. **Constant-Time Verification (`timingSafeEqual`)**:
   - All byte buffer comparisons (GCM authentication tags, SHA-256 chunk digests, and HMAC manifest signatures) are performed in strict constant time using a bitwise XOR accumulator:
   $$\text{diff} = \bigvee_{i=0}^{N-1} (A_i \oplus B_i) == 0$$
   - Prevents side-channel timing attacks that infer key bytes from comparison early-exit latency.

