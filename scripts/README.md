# Ghost-Tag Automation & Build Scripts (`scripts/`)

## 1. Overview
Repository utilities for branding asset generation, Android APK release packaging, compatibility vector fixture generation, webhook signature verification, and automated CI security/quality audits.

## 2. Script Inventory

| Script | Runtime | Purpose |
| :--- | :--- | :--- |
| [`security_audit_agent.py`](security_audit_agent.py) | Python 3 | CI & local security gate checking zero-secrets invariants, `FLAG_SECURE`, cleartext block, C++ checks, 54B/134B overheads, `codeql.yml`, `dependabot.yml`, `SECURITY.md`, and `npm audit`. |
| [`quality_audit_agent.py`](quality_audit_agent.py) | Python 3 | Verifies version alignment (`package.json`, `android/app/build.gradle`, `web/assets/release-meta.json`), strict TypeScript compilation (`tsc --noEmit`), and full Jest test passage. |
| [`package_release_apk.py`](package_release_apk.py) | Python 3 | Runs `:app:assembleRelease` via Gradle (JDK 17+), signs and verifies with `apksigner` using **required** environment variables (`ANDROID_KEY_ALIAS`, `ANDROID_KEYSTORE_PASSWORD`, optional `ANDROID_KEY_PASSWORD`), copies artifact to `web/assets/`, and computes `Ghost-Tag-v2.1.0.apk.sha256` & `release-meta.json`. Fails closed when signing env vars are absent. |
| [`generate_android_branding.py`](generate_android_branding.py) | Python 3 + Pillow | Generates square & circular mipmap launcher icons across `mdpi`..`xxxhdpi` from `web/assets/logo.png`; writes optional composite preview only when `GHOST_TAG_BRANDING_PREVIEW_PATH` is set. |
| [`generate_branding_assets.py`](generate_branding_assets.py) | Python 3 + Pillow | Generates brand logo/favicon assets under `web/`. |
| [`generate_compatibility_fixtures.js`](generate_compatibility_fixtures.js) | Node.js | Regenerates deterministic cross-platform reference vectors in `test-fixtures/recovery/`. |
| [`verify-webhook.js`](verify-webhook.js) | Node.js | Standalone HMAC-SHA-256 verification helper for signed Ghost-Tag webhook payloads. |
| [`patch_dependencies.js`](patch_dependencies.js) | Node.js | Compatibility patch helper for native dependency builds. |

## 3. Usage Examples

```bash
# Run CI security and quality checks locally
python scripts/security_audit_agent.py
python scripts/quality_audit_agent.py

# Package signed release APK (Windows PowerShell — requires signing env vars)
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
$env:ANDROID_KEY_ALIAS = "<your-alias>"
$env:ANDROID_KEYSTORE_PASSWORD = "<your-password>"
python scripts/package_release_apk.py
```

See [`../FAQ.md`](../FAQ.md) and [`../SECURITY.md`](../SECURITY.md) for credential handling rules. Never commit keystores, passwords, or `.env` files.
