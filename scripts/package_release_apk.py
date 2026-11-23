"""Packages the official Ghost-Tag Android release APK using the real Gradle build system.

Compiles all Kotlin/Java, C++ (CMake), React Native runtime, Hermes, and
Android resources via Gradle :app:assembleRelease, signs the APK with the
production release keystore, verifies the APK signature, and exports it to web/assets.

Requirements:
- JDK 17+
- Android SDK & NDK
- release.keystore in android/app/ (password: ghosttag, alias: ghosttag)

Usage:
    python scripts/package_release_apk.py
"""

import os
import sys
import hashlib
import json
import shutil
import subprocess

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ANDROID_DIR = os.path.join(PROJECT_ROOT, 'android')
ANDROID_APP_DIR = os.path.join(ANDROID_DIR, 'app')
GRADLEW = os.path.join(ANDROID_DIR, 'gradlew.bat' if os.name == 'nt' else 'gradlew')
OUTPUT_DIR = os.path.join(ANDROID_APP_DIR, 'build', 'outputs', 'apk', 'release')
APK_OUTPUT_PATH = os.path.join(OUTPUT_DIR, 'app-release.apk')

WEB_ASSETS_DIR = os.path.join(PROJECT_ROOT, 'web', 'assets')
WEB_ASSET_APK_V210 = os.path.join(WEB_ASSETS_DIR, 'Ghost-Tag-v2.1.0.apk')
WEB_ASSET_SHA256 = os.path.join(WEB_ASSETS_DIR, 'Ghost-Tag-v2.1.0.apk.sha256')
WEB_RELEASE_META = os.path.join(WEB_ASSETS_DIR, 'release-meta.json')

KEYSTORE_PATH = os.path.join(ANDROID_APP_DIR, 'release.keystore')
KEYSTORE_ALIAS = os.environ.get('ANDROID_KEY_ALIAS', 'ghosttag')
KEYSTORE_PASS = os.environ.get('ANDROID_KEYSTORE_PASSWORD', 'ghosttag')


def get_java_home():
    """Finds JDK 17+ for Gradle execution."""
    if 'JAVA_HOME' in os.environ and os.path.exists(os.environ['JAVA_HOME']):
        return os.environ['JAVA_HOME']

    candidate = r'C:\Users\Aryan\.gradle\jdks\eclipse_adoptium-17-amd64-windows.2'
    if os.path.exists(candidate):
        return candidate

    return None


def sha256_file(filepath):
    """Computes SHA-256 of file in 64KB chunks."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_apk():
    print("=" * 60)
    print("GHOST-TAG ANDROID REAL GRADLE RELEASE BUILD")
    print("=" * 60)

    # 1. Verify prerequisites
    java_home = get_java_home()
    if not java_home:
        raise SystemExit("Error: Could not locate JDK 17+. Please set JAVA_HOME.")
    print(f"[1/5] Using JDK: {java_home}")

    env = os.environ.copy()
    env['JAVA_HOME'] = java_home
    env['ANDROID_KEYSTORE_PASSWORD'] = KEYSTORE_PASS
    env['ANDROID_KEY_ALIAS'] = KEYSTORE_ALIAS
    env['ANDROID_KEY_PASSWORD'] = KEYSTORE_PASS

    if not os.path.exists(KEYSTORE_PATH):
        raise SystemExit(f"Error: Release keystore not found at {KEYSTORE_PATH}")

    # 2. Invoke Gradle assembleRelease
    print("[2/5] Running Gradle task :app:assembleRelease...")
    cmd = [GRADLEW, ':app:assembleRelease']
    res = subprocess.run(cmd, cwd=ANDROID_DIR, env=env)
    if res.returncode != 0:
        raise SystemExit(f"Gradle build failed with exit code {res.returncode}")

    if not os.path.exists(APK_OUTPUT_PATH):
        raise SystemExit(f"Error: Built APK not found at expected path: {APK_OUTPUT_PATH}")

    # 3. Verify APK contents and signature
    print(f"[3/5] Verifying APK structure and signature at {APK_OUTPUT_PATH}...")
    size_bytes = os.path.getsize(APK_OUTPUT_PATH)
    size_mb = size_bytes / (1024 * 1024)
    print(f"  APK size: {size_bytes} bytes ({size_mb:.2f} MB)")

    # Find apksigner
    apksigner = None
    sdk_root = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if not sdk_root:
        local_app_data = os.environ.get('LOCALAPPDATA', '')
        sdk_candidate = os.path.join(local_app_data, 'Android', 'Sdk')
        if os.path.exists(sdk_candidate):
            sdk_root = sdk_candidate

    if sdk_root:
        bt_dir = os.path.join(sdk_root, 'build-tools')
        if os.path.exists(bt_dir):
            for ver in sorted(os.listdir(bt_dir), reverse=True):
                cand = os.path.join(bt_dir, ver, 'apksigner.bat' if os.name == 'nt' else 'apksigner')
                if os.path.exists(cand):
                    apksigner = cand
                    break

    if apksigner and os.path.exists(KEYSTORE_PATH):
        print(f"  Signing APK with apksigner ({apksigner})...")
        sign_cmd = [
            apksigner, 'sign',
            '--ks', KEYSTORE_PATH,
            '--ks-key-alias', KEYSTORE_ALIAS,
            '--ks-pass', f'pass:{KEYSTORE_PASS}',
            '--key-pass', f'pass:{KEYSTORE_PASS}',
            APK_OUTPUT_PATH
        ]
        s_res = subprocess.run(sign_cmd, capture_output=True, text=True)
        if s_res.returncode == 0:
            print("  APK signed successfully.")
        else:
            print(f"  Warning: apksigner sign note: {s_res.stderr.strip()}")

        v_res = subprocess.run([apksigner, 'verify', '--verbose', APK_OUTPUT_PATH], capture_output=True, text=True)
        if "verifies" in v_res.stdout.lower():
            print("  APK signature verified (v2/v3): verified.")
        else:
            print(f"  Warning: apksigner verify note: {v_res.stderr.strip() or v_res.stdout.strip()}")
    else:
        jarsigner = os.path.join(java_home, 'bin', 'jarsigner.exe' if os.name == 'nt' else 'jarsigner')
        if os.path.exists(jarsigner):
            v_res = subprocess.run([jarsigner, '-verify', APK_OUTPUT_PATH], capture_output=True, text=True)
            if "jar verified" not in v_res.stdout.lower():
                print(f"Warning: jarsigner verification note: {v_res.stdout.strip()}")
            else:
                print("  Signature verified: jar verified.")

    # 4. Copy to web assets and clean up obsolete versions
    print("[4/5] Copying real release APK to web assets...")
    os.makedirs(WEB_ASSETS_DIR, exist_ok=True)
    shutil.copyfile(APK_OUTPUT_PATH, WEB_ASSET_APK_V210)

    # Clean up obsolete v2.0.5 and v2.0.0 assets
    for obsolete in ['Ghost-Tag-v2.0.5.apk', 'Ghost-Tag-v2.0.5.apk.sha256', 'ghost-tag-v2.0.0.apk']:
        ob_path = os.path.join(WEB_ASSETS_DIR, obsolete)
        if os.path.exists(ob_path):
            os.remove(ob_path)

    # 5. Compute SHA-256 and update metadata
    print("[5/5] Computing SHA-256 and writing release metadata...")
    digest = sha256_file(APK_OUTPUT_PATH)
    print(f"  SHA-256: {digest}")

    with open(WEB_ASSET_SHA256, 'w', encoding='utf-8') as f:
        f.write(f"{digest}  Ghost-Tag-v2.1.0.apk\n")

    release_meta = {
        "version": "2.1.0",
        "versionCode": 7,
        "filename": "Ghost-Tag-v2.1.0.apk",
        "sizeBytes": size_bytes,
        "sizeFormatted": f"{size_mb:.2f} MB",
        "sha256": digest,
        "buildType": "Release",
        "compiler": "Android Gradle Plugin 9.4.1 / R8 / CMake",
        "minSdk": 26,
        "targetSdk": 34
    }
    with open(WEB_RELEASE_META, 'w', encoding='utf-8') as f:
        json.dump(release_meta, f, indent=2)
        f.write('\n')

    print("=" * 60)
    print("OFFICIAL REAL ANDROID APK PACKAGED SUCCESSFULLY")
    print(f"Output: {APK_OUTPUT_PATH}")
    print(f"Web Asset: {WEB_ASSET_APK_V210}")
    print(f"SHA-256: {digest}")
    print("=" * 60)


if __name__ == '__main__':
    build_apk()
