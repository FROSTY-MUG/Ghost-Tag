"""Builds the Ghost-Tag iOS app as a standalone .ipa.

Ghost-Tag is a React Native app with an existing Xcode project (ios/GhostTag.xcodeproj).
This script produces a release .ipa directly:

    ios/build/GhostTag.ipa

Requirements: macOS + Xcode + CocoaPods (run on a Mac). The RN workspace
(`npm install`) must already be complete so the native modules can compile.

Usage:
    python3 scripts/package_release_ipa.py
"""

import os
import shutil
import subprocess
import hashlib
import json
import zipfile

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
IOS_DIR = os.path.join(PROJECT_ROOT, 'ios')
BUILD_DIR = os.path.join(IOS_DIR, 'build')
DERIVED_DATA_PATH = os.path.join(BUILD_DIR, 'derived')
APP_PATH = os.path.join(
    DERIVED_DATA_PATH, 'Build', 'Products', 'Release-iphoneos', 'GhostTag.app'
)
IPA_OUTPUT_PATH = os.path.join(BUILD_DIR, 'GhostTag.ipa')
XCODEPROJECT_PATH = os.path.join(IOS_DIR, 'GhostTag.xcodeproj')


def _xcodebuild():
    path = shutil.which('xcodebuild')
    if path is None:
        raise FileNotFoundError(
            'xcodebuild not found. Ghost-Tag iOS packaging requires macOS + Xcode.'
        )
    return path


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def build_ipa():
    xcodebuild = _xcodebuild()

    print('[1/3] Building Ghost-Tag iOS app (Release, iphoneos) via xcodebuild...')
    os.makedirs(BUILD_DIR, exist_ok=True)
    cmd = [
        xcodebuild,
        '-project', XCODEPROJECT_PATH,
        '-configuration', 'Release',
        '-sdk', 'iphoneos',
        '-destination', 'generic/platform=iOS',
        'build',
        '-derivedDataPath', DERIVED_DATA_PATH,
    ]
    res = subprocess.run(cmd, cwd=IOS_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout[-2000:])
        print(res.stderr[-2000:])
        raise SystemExit(f'xcodebuild failed with exit code {res.returncode}')
    print('    -> xcodebuild Release build completed.')

    print(f'[2/3] Verifying app bundle exists: {APP_PATH}...')
    if not os.path.isdir(APP_PATH):
        raise FileNotFoundError(f'App bundle missing: {APP_PATH}')
    print('    -> app bundle found.')

    print(f'[3/3] Packaging .ipa: {IPA_OUTPUT_PATH}...')
    if os.path.exists(IPA_OUTPUT_PATH):
        os.remove(IPA_OUTPUT_PATH)
    with zipfile.ZipFile(IPA_OUTPUT_PATH, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.write(APP_PATH, 'Payload/GhostTag.app')

    size_bytes = os.path.getsize(IPA_OUTPUT_PATH)
    size_mb = size_bytes / (1024 * 1024)
    digest = _sha256(IPA_OUTPUT_PATH)

    print('=' * 60)
    print('GHOST-TAG iOS .IPA CREATED SUCCESSFULLY')
    print(f'Path: {IPA_OUTPUT_PATH}')
    print(f'Size: {size_bytes} bytes ({size_mb:.2f} MB)')
    print(f'SHA-256: {digest}')
    print('Note: distribute via TestFlight or an enterprise provisioning profile;')
    print('App Store distribution uses the Xcode Organizer or `xcodebuild -exportArchive`.')
    print('=' * 60)

    # Write shared release metadata used by the website/scripts
    meta_path = os.path.join(PROJECT_ROOT, 'web', 'assets', 'ios-release-meta.json')
    os.makedirs(os.path.dirname(meta_path), exist_ok=True)
    with open(meta_path, 'w') as out:
        json.dump({
            'platform': 'ios',
            'file': 'GhostTag.ipa',
            'sha256': digest,
            'sizeBytes': size_bytes,
            'sizeFormatted': f'{size_mb:.2f} MB',
        }, out, indent=2)
        out.write('\n')
    print(f'Metadata: {meta_path}')


if __name__ == '__main__':
    build_ipa()
