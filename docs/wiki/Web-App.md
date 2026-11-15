# Ghost-Tag Web Client

The Ghost-Tag Web Client is a lightweight, zero-installation companion app hosted on GitHub Pages:
[https://frosty-mug.github.io/Ghost-Tag/](https://frosty-mug.github.io/Ghost-Tag/)

---

## 1. Compatibility & Browser Support

The Web NFC API (`NDEFReader`) is required to read and write physical NFC tags from a browser.

| Platform | Browser | Web NFC Support | Notes |
| :--- | :--- | :--- | :--- |
| **Android** | Google Chrome | Supported | Requires HTTPS and user gesture |
| **Android** | Chromium (Edge, Brave, Opera) | Supported | Web NFC flag enabled by default |
| **Android** | Firefox / Samsung Internet | Unsupported | Web NFC not implemented |
| **iOS / iPadOS** | Safari / Chrome / Any | Unsupported | iOS does not expose Web NFC in browsers |
| **Windows / macOS / Linux** | Desktop Browsers | Emulation Mode | Full simulated Web NFC testing suite built-in |

> **Note on iOS**: Apple does not provide the Web NFC API in iOS WebKit. iOS users can open the site in recovery mode or wait for the dedicated Ghost-Tag iOS app.

---

## 2. Security Properties

- **Static Deployment**: The site contains no server-side executable code; all crypto runs client-side via Web Cryptography API (`crypto.subtle`).
- **Zero Local Plaintext Persistence**: Passphrases and decrypted files reside purely in volatile memory. Decrypted files are wiped when you tap `Clear Temporary Data` or close the browser tab.
- **Strict HTTPS**: Web NFC is strictly disabled by browsers on unencrypted connections. GitHub Pages enforces HTTPS with modern TLS certificates.
- **No Scanned Chunk Cache**: Following Section 18 of the specification, scanned chunks are never stored in `localStorage` or `IndexedDB`.
