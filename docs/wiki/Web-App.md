# Ghost-Tag Web App (`v2.1.0` Staging)

The Ghost-Tag Web Companion provides offline-first client-side encryption, vendored `hash-wasm` Argon2id WASM recovery derivation, Cloudflare Turnstile-gated Supabase recovery, and hardware NFC operations.

**Live URL**: [https://frosty-mug.github.io/Ghost-Tag/](https://frosty-mug.github.io/Ghost-Tag/)

---

## Browser & Hardware NFC Matrix

| Platform | Browser | Hardware NFC Path | Behavior & Status |
| :--- | :--- | :--- | :--- |
| **Android** | Google Chrome (`89+`) | Web NFC API (`NDEFReader`) | Works over HTTPS (`https://frosty-mug.github.io/Ghost-Tag/`); pending real Android Chrome hardware tap pass. |
| **Windows / macOS / Linux** | Chrome / Edge / Chromium | **Ghost Bridge** (`ws://127.0.0.1:41789`) | Connects strictly to physical USB PC/SC or PN532 readers with CSPRNG `sessionToken` auth. **No simulated or synthetic transceiver exists.** |
| **iOS** | Safari / Chrome iOS | **Not Supported** | Apple iOS exposes no Web NFC API to browsers; native iOS (`#25`) is deferred to `iOS Beta`. |

See [Ghost Bridge](Ghost-Bridge), [NFC Compatibility](NFC-Compatibility), and [`../../FAQ.md`](../../FAQ.md).
