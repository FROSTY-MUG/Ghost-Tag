# Ghost-Tag Web Companion (`web/`, v2.1.0 Staging)

## 1. Purpose
Client-side encrypted NFC web companion built with Vite (`vite@6.4.6`), WebCrypto AES-256-GCM, vendored offline `hash-wasm` Argon2id WebAssembly (`vendor/argon2.umd.min.js`), Cloudflare Turnstile integration, Android Chrome Web NFC (`NDEFReader`), and local WebSocket RPC to Desktop **Ghost Bridge** (`127.0.0.1:41789`).

**Live Pages Deployment**: [https://frosty-mug.github.io/Ghost-Tag/](https://frosty-mug.github.io/Ghost-Tag/)

## 2. Browser & Hardware Support

| Platform | Browser | NFC Hardware Path | Status |
| :--- | :--- | :--- | :--- |
| **Android** | Google Chrome (89+) | Web NFC API (`NDEFReader`) | Requires HTTPS context (`https://frosty-mug.github.io/Ghost-Tag/` or port-forwarded localhost); pending physical handset tag pass. |
| **Desktop** | Chrome / Edge / Chromium | **Ghost Bridge** (`ws://127.0.0.1:41789` + USB reader) | Hardware-only bridge using per-connection `sessionToken`. **Zero synthetic or simulation mode.** |
| **iOS** | Safari / Chrome iOS | Unsupported by browser APIs | Apple iOS exposes no Web NFC API to browsers; native iOS target (`#25`) is deferred to `iOS Beta`. |

## 3. Build, Audit & Architecture
- **Multi-View Showcase & App**: [`index.html`](index.html), [`app/`](app/index.html), [`technical.html`](technical.html), [`docs/technical.md`](docs/technical.md), [`styles.css`](styles.css).
- **Cryptography & Cloud Recovery**: [`app.js`](app.js), [`crypto-simulator.js`](crypto-simulator.js), [`supabase.js`](supabase.js), [`src/supabaseClient.ts`](src/supabaseClient.ts), [`wordlist.js`](wordlist.js), [`vendor/argon2.umd.min.js`](vendor/argon2.umd.min.js).
- **Release Metadata Note**: [`index.html`](index.html) links the latest published GitHub Release (`v2.0.6`), while [`assets/release-meta.json`](assets/release-meta.json) and [`assets/Ghost-Tag-v2.1.0.apk.sha256`](assets/Ghost-Tag-v2.1.0.apk.sha256) track the local staging APK (`077ecdb3ec3c052b5c30ec52d884e56461209cf92eb0cc1fe93ddd8214723952`, `39.45 MB`). `v2.1.0` has not yet been tagged or published on GitHub Releases.

```bash
# Install and build production bundle into web/dist/
npm --prefix web ci
npm --prefix web run build
npm --prefix web audit --audit-level=moderate
```

See [`../FAQ.md`](../FAQ.md) and [`releases/README.md`](releases/README.md) for verification details.
