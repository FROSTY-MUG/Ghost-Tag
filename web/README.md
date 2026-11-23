# Ghost-Tag Web Client (v2.1.0)

Ghost-Tag Web is a minimal, dark, client-side encrypted NFC storage application deployed to GitHub Pages. It enables writing, scanning, and decrypting Ghost-Tag data directly within modern web browsers.

**Live Deployment**: [https://frosty-mug.github.io/Ghost-Tag/](https://frosty-mug.github.io/Ghost-Tag/)

---

## 1. Features

- **Encrypted NFC Storage**: Single-tag and bulk multi-tag vault writing with AES-256-GCM.
- **Stop and Pause Scanning/Writing**: Explicit control over hardware scan loops with state preservation.
- **BIP-39 12-Word Recovery**: Cross-platform interoperability with Ghost-Tag Android.
- **72-Hour Ephemeral Cache**: IndexedDB cache for paused sessions and fast resumption.
- **Automatic Chip Detection**: Transparent handling of NTAG213, NTAG215, and NTAG216 tags.
- **Zero-Secrets Policy**: Completely client-side execution; no plaintext or keys ever touch a server.

---

## 2. Browser Compatibility & Web NFC

| Platform | Browser | Web NFC Support | Notes |
| :--- | :--- | :--- | :--- |
| **Android** | Google Chrome (89+) | **Full Support** | Requires HTTPS context. Supports NDEF reading and writing. |
| **Android** | Other Chromium Browsers | Varies | Edge/Opera for Android support Web NFC when enabled. |
| **iOS** | Safari / Chrome | **No Web NFC** | iOS does not expose Web NFC API to browsers; use Android APK. |
| **Desktop** | Chrome / Firefox / Safari | **Simulation Mode** | Automatic simulated transceiver for testing and vault management. |

---

## 3. Development & Local Testing

```bash
cd web

# Run locally using any static file server
python -m http.server 8080

# Or with Vite
npm install
npm run dev
```

Visit `http://localhost:8080` in your browser. On Android devices with USB debugging, use Chrome DevTools port forwarding to access `http://localhost:8080` with Web NFC enabled.
