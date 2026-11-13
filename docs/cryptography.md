# Ghost-Tag Cryptographic Core Specification

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

- **Mnemonic Encoding**: 256 bits of CSPRNG entropy + 8-bit SHA-256 checksum = 264 bits $\rightarrow$ encoded into 24 BIP39 words.
- **Isolated Parameters**: Uses a dedicated 32-byte salt and independent Argon2id work factors distinct from the primary passphrase KDF.
- **Recovery Envelope**: Stored locally or exported to allow recreating access to tag DEKs if the primary passphrase is lost.

---

## 6. Memory Zeroization

Ghost-Tag implements defense-in-depth buffer sanitization:
- Ephemeral KEKs, unwrapped DEKs, and plaintext buffers are actively overwritten with `0x00` bytes immediately upon completion of cryptographic tasks (`zeroize()`).
- The application automatically locks and zeroizes in-memory session keys when backgrounded or inactive.
- *Notice*: While JavaScript garbage collectors may hold unreachable string remnants in heap memory, typed `Uint8Array` byte buffers are scrubbed in place.
