# Ghost Bridge Desktop Companion (`v2.1.0`)

**Ghost Bridge** connects physical USB NFC readers (ACS ACR122U via PC/SC, plus ESP32/PN532 serial protocol support) to browsers using a local loopback server on `127.0.0.1:41789`.

---

## 1. Loopback Transport & Origin / Session Security

```text
Browser (HTTPS / localhost) ──ws://127.0.0.1:41789──> Ghost Bridge (desktop/src/server.js) ──PC/SC APDU──> Physical ACR122U + NTAG21x
```

1. **Strict Loopback Binding**: Listens on `127.0.0.1:41789` only.
2. **Origin Validation (`isBridgeOriginAllowed`)**: Rejects unauthorized origins with HTTP `403 FORBIDDEN_ORIGIN`. Only `https://frosty-mug.github.io`, approved `GHOST_APPROVED_ORIGINS`, and non-production loopback origins are permitted.
3. **Per-Connection `sessionToken` Enforcement**: On WebSocket connect, Ghost Bridge issues a CSPRNG 24-byte hex `sessionToken` in `bridge_status`. Clients must include `sessionToken` in `read_tag` and `write_tag` payloads; verification uses `crypto.timingSafeEqual` and allowlisted `actionHandlers` `Map` checks.
4. **MIME & Payload Guards**: Only `application/vnd.ghost.secure` and `application/vnd.ghost.bulk` up to `8192` byte integers are accepted.
5. **Zero Synthetic Data**: `simulate_tag` is always rejected (`Non-negotiable product rule: Synthetic or simulated NFC data is strictly prohibited`).

## 2. Running Locally

```bash
node desktop/bin/ghost-bridge.js
```

### Example `GET http://127.0.0.1:41789/status` Response

```json
{
  "bridge": "Ghost Bridge",
  "version": "2.1.0",
  "status": "ready",
  "readers": [],
  "hasAcr122u": false,
  "cardPresent": false,
  "activeCardUid": null,
  "supportedReaders": ["ACS ACR122U USB NFC Reader"]
}
```

Physical ACR122U and ESP32/PN532 reader testing remains an open hardware validation gate ([`../../PROJECT-STATUS.md`](../../PROJECT-STATUS.md)).
