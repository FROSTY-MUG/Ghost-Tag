# NFC Compatibility Matrix

Ghost-Tag is engineered specifically for **NFC Forum Type 2 Tags** (ISO/IEC 14443-3A), the most ubiquitous and cost-effective NFC standard in the world.

---

## 1. Supported Chip Families

| Chip Family | Total Memory | NDEF User Memory | Usable Ghost Payload | Typical Form Factors |
| :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | 180 bytes | 144 bytes | **~96–100 bytes** | Micro-stickers, key tags |
| **NTAG215** | 540 bytes | 504 bytes | **~450–460 bytes** | Standard NFC cards, coins |
| **NTAG216** | 924 bytes | 888 bytes | **~830–844 bytes** | High-capacity badges, rings |

---

## 2. Automatic Hardware Detection

Ghost-Tag **never** asks users to manually select their chip model. Instead, Ghost-Tag inspects the tag's Capability Container (CC byte page 03) during the initial NDEF handshake:

```text
Tag detected.
Total storage: 504 bytes
Writable storage: 496 bytes
```

### Detection Mechanics:
- `CC[2]` contains the memory size byte (`size_byte * 8` bytes of memory).
- If `CC[2] == 0x12` (18): Tag is **NTAG213** (144 bytes).
- If `CC[2] == 0x3E` (62): Tag is **NTAG215** (504 bytes).
- If `CC[2] == 0x6D` (109): Tag is **NTAG216** (888 bytes).

---

## 3. Unsupported Tag Types

| Tag Family | Reason for Exclusion |
| :--- | :--- |
| **MIFARE Classic 1K / 4K** | Proprietary Crypto-1 cipher; violates NFC Forum standard; incompatible with many modern Android NFC controllers. |
| **MIFARE Ultralight (old 64B)** | Insufficient capacity (< 106 bytes overhead). |
| **NFC Forum Type 4 (DESFire / SmartMX)** | Complex file system APDUs; unnecessary cost and overhead for basic distributed cold storage. |
| **FeliCa (Type 3)** | High licensing costs and regional hardware constraints. |
