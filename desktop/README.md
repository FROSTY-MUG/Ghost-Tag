# Ghost Bridge — Desktop Hardware NFC Daemon (`v2.1.0`)

## 1. Purpose
Local loopback desktop daemon connecting physical USB PC/SC NFC readers (such as the ACS ACR122U) and serial PN532/ESP32 bridges to browsers over `http://127.0.0.1:41789` and `ws://127.0.0.1:41789`. Ghost Bridge strictly forbids synthetic or simulated NFC events (`simulate_tag` always returns an error).

## 2. Security & Transport Architecture
- [`src/server.js`](src/server.js):
  - Binds strictly to `127.0.0.1:41789` (`HOST = '127.0.0.1'`).
  - Enforces strict Origin validation on both HTTP (`/status`) and WebSocket handshakes (`isBridgeOriginAllowed`, HTTP `403 FORBIDDEN_ORIGIN` without wildcard CORS). Approved origins: `https://frosty-mug.github.io`, validated HTTPS entries in `GHOST_APPROVED_ORIGINS`, and loopback origins in non-production mode.
  - Issues a per-connection 24-byte CSPRNG hex `sessionToken` (`crypto.randomBytes(24)` stored in `WeakMap`) and requires constant-time token verification (`crypto.timingSafeEqual`) before `read_tag` or `write_tag`.
  - Validates message actions through an allowlisted `Map` (`has()` + callable check), restricts `envelopeBytes` to `1..8192` byte integers, and allowlists MIME types (`application/vnd.ghost.secure`, `application/vnd.ghost.bulk`).
- [`src/apdu.js`](src/apdu.js): PC/SC APDU commands for Type 2 tag identification, TLV + NDEF MIME serialization, and mandatory read-back SHA-256 write verification.
  - Exact `apdu.js` framing limits (`calculateTagCapacity`):
    - **NTAG213 (`144B` user EEPROM)**: v1 max ciphertext `56B`; v2 bulk **`fits: false` (`0B`)**.
    - **NTAG215 (`504B` user EEPROM)**: v1 max ciphertext `411B`; v2 bulk `333B`.
    - **NTAG216 (`888B` user EEPROM)**: v1 max ciphertext `795B`; v2 bulk `717B`.
- [`src/transports/serialTransport.js`](src/transports/serialTransport.js) & [`firmware/esp32_pn532/`](firmware/esp32_pn532/README.md): Serial framing protocol for ESP32 + PN532 hardware.
- [`bin/ghost-bridge.js`](bin/ghost-bridge.js): CLI entry point.

## 3. Running & Testing

```bash
# Start local bridge (PC/SC driver active when hardware is connected)
node desktop/bin/ghost-bridge.js

# Run Ghost Bridge standalone + HTTP/WebSocket security tests
node desktop/test/bridge.test.js

# Run via workspace Jest (included in npm test) & PN532 serial suite (22 tests)
npm test -- desktop/test/bridge.test.js
npx jest desktop/test/pn532_serial.test.js
```

## 4. Hardware Verification Status
All protocol logic, session-token enforcement, origin guards, NDEF capacity bounds, and PN532 framing tests pass locally (`bridge.test.js` and 22 tests in `pn532_serial.test.js`). Live hardware validation against physical ACS ACR122U USB readers and physical ESP32 + PN532 modules with real NTAG21x tags remains pending (`../PROJECT-STATUS.md`, [`../FAQ.md`](../FAQ.md)).
