# Ghost Bridge

Ghost Bridge is the lightweight native desktop companion daemon for Ghost-Tag. It bridges local PC/SC USB NFC hardware—specifically the **ACS ACR122U USB NFC Reader**—to the Ghost-Tag web application running in modern desktop web browsers (Chrome, Edge, Firefox, Brave, Safari).

```
 +-------------------------------------------------------+
 |                 Ghost-Tag Web Client                  |
 |            (https://frosty-mug.github.io/Ghost-Tag/)  |
 +---------------------------+---------------------------+
                             |
                   WebSocket / HTTP RPC
                 (ws://127.0.0.1:41789)
                             |
 +---------------------------v---------------------------+
 |               Ghost Bridge Daemon                     |
 |                   (desktop/)                          |
 +---------------------------+---------------------------+
                             |
                        PC/SC APDUs
                             |
 +---------------------------v---------------------------+
 |           ACS ACR122U USB NFC Reader                  |
 |                   (Hardware)                          |
 +-------------------------------------------------------+
```

---

## 1. Why Ghost Bridge?

Web browsers running on desktop operating systems (macOS, Linux, Windows) do not expose the W3C Web NFC API (`window.NDEFReader`), which is currently restricted to Chromium on Android.

Ghost Bridge solves this limitation with zero-trust local hardware communication:
- Binds strictly to `127.0.0.1:41789` (local loopback only).
- Exposes real PC/SC smartcard transceiver events (`card_present`, `card_removed`).
- Executes low-level APDUs directly to read and write Type 2 NDEF records on NTAG chips.
- Cryptographically verifies every written block with a read-back SHA-256 hash check.
- **Zero Synthetic Data**: If the ACR122U reader is not connected or no card is placed on the antenna, the bridge reports physical hardware status directly—no simulated tags or fake data.

---

## 2. Supported Hardware

| Hardware | Support Status | Protocol |
| :--- | :--- | :--- |
| **ACS ACR122U USB NFC Reader** | **Primary Full Support** | PC/SC (ISO/IEC 14443 Type A, Type 2 NTAG213/215/216) |
| **ACR1252U / ACR1255U** | Compatible | PC/SC APDU pass-through |
| **Generic CCID NFC Readers** | Partial (tag UID & raw APDU) | PC/SC |
| **Proxmark3 / Flipper Zero** | **Not Supported** | Out of scope (Ghost-Tag is for persistent storage, not security research) |

---

## 3. Installation & Setup

### Prerequisites
- Node.js v18.0.0 or higher.
- Operating system PC/SC drivers:
  - **Windows**: Built-in Windows Smart Card service (`SCardSvr`) and official ACS ACR122U driver.
  - **macOS**: Built-in `pcscd` daemon (no drivers needed for ACR122U).
  - **Linux**: `sudo apt install pcscd libpcsclite-dev` and start service (`sudo systemctl enable --now pcscd`).

### Running Ghost Bridge

From the repository root:
```bash
cd desktop
npm install
npm start
```

Or run via the CLI binary:
```bash
./bin/ghost-bridge.js --port 41789
```

When started, Ghost Bridge outputs:
```
[Ghost Bridge] v2.0.5 initializing...
[Ghost Bridge] Bound strictly to 127.0.0.1:41789
[Ghost Bridge] PC/SC Reader initialized: ACS ACR122U 0
[Ghost Bridge] Ready for Ghost-Tag web client connections.
```

---

## 4. Hardware States & Status API

Ghost Bridge provides both an HTTP diagnostic endpoint and a real-time WebSocket feed.

### HTTP Health Check
```http
GET http://127.0.0.1:41789/status
```

Response when reader is plugged in:
```json
{
  "bridge": "Ghost Bridge",
  "version": "2.0.5",
  "status": "ready",
  "readers": ["ACS ACR122U 0"],
  "hasAcr122u": true,
  "cardPresent": false,
  "activeCardUid": null,
  "supportedReaders": ["ACS ACR122U USB NFC Reader"]
}
```

### Hardware Status Invariants in Web UI

1. **Laptop without Ghost Bridge or USB reader**:
   ```
   NO USB NFC READER DETECTED
   [Download Ghost Bridge]  [Use Android App]
   ```
2. **Laptop with Ghost Bridge and USB reader, no card on antenna**:
   ```
   NO NFC TAG DETECTED
   Please place an NFC tag on the USB reader antenna.
   ```
3. **Card detected on antenna**:
   ```
   TAG DETECTED: 04:A1:B2:C3:D4:E5:F6 (NTAG215)
   Writable: 496 Bytes | Ghost Storage: 362 Bytes
   ```

---

## 5. Security & Isolation

- **Localhost Only**: Ghost Bridge strictly binds to `127.0.0.1` and never opens external interfaces (`0.0.0.0`).
- **Zero Plaintext Logs**: Payloads sent through Ghost Bridge are already encrypted via AES-256-GCM. The bridge never handles plaintext keys, passphrases, or seed phrases.
- **Strict Read-Back Verification**: Every write operation executes an APDU block read across all written pages, recomputes the SHA-256 digest, and compares it against the expected ciphertext hash before declaring write success.
