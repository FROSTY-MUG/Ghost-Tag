# Encrypt Flow

The Encrypt workflow allows you to bundle arbitrary data, encrypt it under AES-256-GCM, and write it across one or multiple physical NFC tags.

---

## 1. Step-by-Step Flow

```text
[ Encrypt ]
    │
    ▼
[ Start Scanning ] ──► Tap NFC Tags ──► Auto-detect capacity
    │
    ▼
[ End Scanning Process ] ──► Usable Ghost storage calculated
    │
    ▼
[ Add Content ] ──► Text / File / Photo / Video / URL
    │
    ▼
[ Write Everything ] / [ Encrypt and Write ]
    │
    ▼
[ Enter Passphrase ] ──► Derive KEK ──► Encrypt AES-256-GCM ──► Split chunks
    │
    ▼
[ Write & Verify Loop ] ──► Write tag ──► Read back tag ──► Verify hash
    │
    ▼
[ Complete ] ──► "32 tags written and verified."
```

---

## 2. Supported Entry Types

1. **Text**: Arbitrary UTF-8 notes, private recovery codes, or credentials.
2. **File**: Any binary document (PDF, ZIP, JSON, binaries, etc.). Treated strictly as binary bytes without modification.
3. **Photo**: Images (JPEG, PNG, WebP).
4. **Video**: Video clips (MP4, MKV, etc.).
5. **URL**: Private URLs (e.g. `https://vault.internal/secret`). **All URLs are encrypted by default** in v2.0.5; Ghost-Tag never writes plain unencrypted NDEF URI records.

---

## 3. Automatic Capacity Calculation

Ghost-Tag automatically detects tag hardware (NTAG213, NTAG215, NTAG216) and computes writable capacity after accounting for the 106-byte envelope overhead:

```text
Usable Ghost Storage = Total Writable Bytes - (106 bytes × Number of Tags)
```

- If content exceeds total capacity:
  ```text
  NOT ENOUGH NFC STORAGE
  Content size: 3.35 MB
  Usable Ghost storage: 5.83 KB
  Scan more NFC tags or remove entries.
  [Scan More Tags]  [Remove Entry]
  ```
- If more tags were scanned than needed:
  ```text
  CONTENT READY
  Required tags: 32
  Scanned tags: 40
  Extra tags: 8
  Only 32 tags are required. Please set aside the other 8 tags.
  [Use 32 Tags]
  ```

---

## 4. Atomic Write & Read-Back Verification

Ghost-Tag enforces strict write verification. A tag is never marked complete until:
1. NDEF record is transmitted to the tag.
2. Tag is read back in its entirety.
3. Binary envelope magic (`GTAG`) and headers are validated.
4. AES-256-GCM authentication tag is verified.
5. SHA-256 checksum of the ciphertext matches expected chunk hash.
