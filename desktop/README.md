# Ghost Bridge v2.1.0

**Native Desktop PC/SC USB NFC Hardware Companion for Ghost-Tag**

Ghost Bridge is a lightweight, zero-cloud desktop companion application that enables the Ghost-Tag web client to interact with real USB NFC readers on laptops and desktop computers.

---

## Architecture

```
Laptop Browser (Web Client)
           │
           │  WebSocket / JSON (ws://127.0.0.1:41789)
           ▼
Ghost Bridge Desktop Companion (Node.js / PC/SC)
           │
           │  WinSCard / pcscd APDUs
           ▼
Physical USB NFC Reader (ACR122U)
           │
           │  13.56 MHz RF Field (ISO 14443-4A / Type 2)
           ▼
Physical NFC Tag (NTAG213 / NTAG215 / NTAG216)
```

---

## Supported Hardware Compatibility List

| Hardware Model | Type | Connectivity | Driver Stack | Status |
| :--- | :--- | :--- | :--- | :--- |
| **ACS ACR122U** | USB NFC Reader / Writer | USB 2.0 Full Speed | PC/SC (`WinSCard` / `pcscd`) | **Verified Baseline** |
| **ACS ACR1252U** | USB NFC Reader / Writer | USB 2.0 Full Speed | PC/SC (`WinSCard` / `pcscd`) | Compatible |
| **Identiv uTrust 3700 F** | USB NFC Reader | USB 2.0 | PC/SC | Compatible |
| **Sony RC-S380 (PaSoRi)**| USB NFC Reader | USB 2.0 | PC/SC | Compatible |

> [!IMPORTANT]
> Ghost-Tag v2.1.0 officially targets the **ACS ACR122U USB NFC Reader**. Other PC/SC-compliant readers may work if they expose standard ISO 14443 Type 2 Tag APDUs, but ACR122U is the verified baseline.

---

## Tag Capability & Model Detection

Ghost Bridge automatically queries Block 3 (Capability Container `CC`) upon tag tap to dynamically detect tag model, writable memory bounds, and lock status:

| Tag Model | CC Byte 2 (Size) | Total EEPROM | User Writable Memory | Typical Usage |
| :--- | :--- | :--- | :--- | :--- |
| **NXP NTAG213** | `0x12` | 180 Bytes | 144 Bytes (Blocks 4–39) | Single-Tag Ghost v1 Envelopes |
| **NXP NTAG215** | `0x3E` | 540 Bytes | 496 Bytes (Blocks 4–129) | Multi-Entry Vault Chunks |
| **NXP NTAG216** | `0x6D` | 924 Bytes | 872 Bytes (Blocks 4–221) | Bulk Ghost v2 Envelopes |

Pre-flight checks automatically reject non-Type 2 tags, read-only/locked tags (`CC[3] & 0x0F != 0`), and payloads that exceed the physical tag capacity before any write operation is attempted.

---

## Non-Negotiable Invariants

1. **Zero Synthetic / Simulated Tags**: Ghost Bridge refuses to fabricate, simulate, or mock NFC tags or capacity values. It communicates solely through real PC/SC smart card events.
2. **Local-Only Binding**: Ghost Bridge binds strictly to `127.0.0.1:41789`. It never exposes endpoints to the local network or internet.
3. **Hardware Truth**: If no reader is plugged in, it reports `NO USB NFC READER DETECTED`. If no card is on the antenna, it reports `NO NFC TAG DETECTED`.
4. **Cryptographic Verification**: Every write operation executes a physical read-back pass that parses the NDEF record, verifies the 16-byte AES-GCM authentication tag, and checks the 32-byte SHA-256 ciphertext hash.

---

## Prerequisites

- **Windows**: The built-in *Smart Card* service must be running (`ScardSvr`). ACS ACR122U drivers are usually installed automatically via Windows Update.
- **macOS**: Built-in `PCSC.framework` is active by default.
- **Linux**: Requires `pcscd` and `libpcsclite-dev`:
  ```bash
  sudo apt-get install pcscd libpcsclite-dev
  sudo systemctl enable --now pcscd
  ```

---

## Installation & Usage

1. Navigate to the desktop directory:
   ```bash
   cd desktop
   npm install
   ```

2. Start the bridge:
   ```bash
   npm start
   ```

3. Open the Ghost-Tag web client in your laptop browser:
   [https://frosty-mug.github.io/Ghost-Tag/](https://frosty-mug.github.io/Ghost-Tag/)

4. When you tap **Start Scanning**, Ghost-Tag automatically detects the active Ghost Bridge connection and begins receiving real card-present events.
