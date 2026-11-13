# Ghost-Tag Strict Security & Multi-Language Hardening Specification

This document details the multi-language defense-in-depth architecture implemented in Ghost-Tag to protect against reverse engineering, dynamic instrumentation, memory dumping, side-channel attacks, and leakage of passphrase hash values or cryptographic keys.

---

## 1. Multi-Language Architectural Model

| Layer | Primary Language | Role & Defense-in-Depth Mechanisms |
|---|---|---|
| **Native Core** | **C++17 / Linux ABI** | Low-level kernel syscalls, `ptrace` anti-debugging, `/proc` filesystem integrity inspection, memory page locking (`mlock`), non-optimizable volatile zeroization barriers. |
| **Platform Gateway** | **Kotlin / Java** | Android OS platform controls, `WindowManager.LayoutParams.FLAG_SECURE` screen capture blocking, Android KeyStore hardware-backed master key (TEE / StrongBox). |
| **Application Layer** | **TypeScript** | Fail-closed device integrity coordinator, multi-pass buffer wiping (`0xAA`, `0x55`, random, `0x00`), log sanitization, constant-time comparisons (`timingSafeEqual`). |
| **Bytecode Obfuscator** | **ProGuard / R8** | Aggressive class repackaging (`com.ghosttag.obf`), dead-code stripping, log elimination, symbol and line number stripping. |

---

## 2. Native C++ Security Engine (`libghosttag_security.so`)

The native core compiles directly into machine code for ARM64 (`arm64-v8a`), ARMv7 (`armeabi-v7a`), x86, and x86_64, bypassing Dalvik/ART bytecode hook points.

### 2.1 Anti-Debugging & Tracer Detection
1. **`ptrace(PTRACE_TRACEME, 0, 1, 0)`**:
   - Under the Linux kernel model, only one tracer can attach to a process via `ptrace`.
   - If an attacker attaches GDB, LLDB, or IDA Pro debugger, `ptrace(PTRACE_TRACEME)` immediately returns `-1` (`EPERM`), flagging an active debugger.
2. **`/proc/self/status` TracerPid Inspection**:
   - Reads the `/proc/self/status` pseudo-file.
   - Parses `TracerPid:\t<pid>`. Any value greater than `0` indicates an active debugger or tracing tool.
3. **`/proc/self/wchan` Inspection**:
   - Inspects the wait channel of the calling process for `sys_ptrace` or `ptrace_stop`.

### 2.2 Anti-Hooking & Dynamic Instrumentation
1. **`/proc/self/maps` Memory Mapping Scan**:
   - Parses memory segments to detect injected libraries used by dynamic instrumentation frameworks:
     - **Frida**: `frida-agent.so`, `frida-gadget`, `libfrida`, `gum-js-loop`, `gmain`
     - **Xposed / LSPosed / EdXposed**: `libxposed`, `XposedBridge`, `edxposed`, `sandhook`
     - **Substrate**: `libsubstrate.so`, `cydiasubstrate.so`
2. **Frida Server Default Port Detection**:
   - Attempts non-blocking socket connection to `127.0.0.1:27042` to detect active Frida injection servers.

### 2.3 Privilege Escalation & Root Detection
1. **Binary Filesystem Check**:
   - Checks presence of known `su` binaries across system paths:
     - `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/data/local/su`, `/data/local/bin/su`, `/data/local/xbin/su`, `/system/sd/xbin/su`, `/system/app/Superuser.apk`, `/data/adb/magisk`, `/data/adb/ksu`
2. **Build Property Validation**:
   - Reads system properties via `__system_property_get`:
     - Checks `ro.debuggable != 1`
     - Checks `ro.secure != 0`

---

## 3. Secure Memory & Anti-Dumping Protection

### 3.1 Kernel Page Locking (`mlock`)
- Passphrase buffers, intermediate Argon2 hash states, and Key Encryption Keys (KEKs) are pinned to physical RAM using `mlock(addr, len)`.
- **Guarantee**: The Linux kernel is forbidden from swapping or paging these memory regions out to swap partitions or flash storage, eliminating persistent remnants across device power cycles.

### 3.2 Multi-Pass Volatile Memory Scrubbing
To defeat compiler optimization (dead-store elimination) and cold-boot physical RAM remanence:
1. **Pass 1**: Overwrite entire buffer with alternating bit pattern `0xAA` (`10101010`).
2. **Compiler Memory Barrier**: `asm volatile("" : : "r"(addr) : "memory")` forces Clang/LLVM to emit the stores without reordering.
3. **Pass 2**: Overwrite with inverse bit pattern `0x55` (`01010101`).
4. **Compiler Memory Barrier**: Second barrier enforcing volatile execution.
5. **Pass 3**: Overwrite with cryptographically secure random bytes (QuickCrypto).
6. **Pass 4**: Complete zeroization `0x00`.

### 3.3 Passphrase & Hash Value Protection
- **No Static Key Retention**: KEKs exist only in ephemeral `VaultSession` state.
- **Immediate Scrubbing**: Intermediate buffers generated during PBKDF2 or Argon2 derivations are wiped in `finally` blocks.
- **Constant-Time Verification**: All byte array comparisons use `timingSafeEqual()` (bitwise XOR accumulator) to eliminate timing side channels.

---

## 4. Android Platform & Kotlin Controls

### 4.1 Window `FLAG_SECURE`
- `MainActivity.kt` enforces `WindowManager.LayoutParams.FLAG_SECURE` in `onCreate()` and `onResume()`.
- **Guarantees**:
  - The Android OS blocks screen capture, screen recording, and casting.
  - The Android Recent Apps / Task Switcher renders a blank/obscured card instead of exposing sensitive vault screens or decrypted notes.

### 4.2 Hardware-Backed KeyStore Master Key (`KeyStoreMasterKey.kt`)
- Generates an AES-256-GCM key inside the Android KeyStore (`AndroidKeyStore`).
- Backed by hardware: Trusted Execution Environment (TEE) or StrongBox Keymaster.
- Encrypts the local database encryption key so that even if the app's internal database files are extracted from a rooted phone, the root key cannot be extracted without hardware authentication.

### 4.3 Network & Manifest Hardening
- `android:allowBackup="false"` prevents ADB backup extraction.
- `android:extractNativeLibs="false"` prevents uncompressed libraries from being tampered with in storage.
- `network_security_config.xml` strictly disables cleartext HTTP traffic across all domains.

---

## 5. Bytecode Obfuscation & R8 Configuration

`android/app/proguard-rules.pro` configures aggressive R8 rules:
- **Package Flattening**: `-repackageclasses 'com.ghosttag.obf'` collapses all class packages into a single flat namespace to obfuscate structural architecture.
- **Symbol Stripping**: Removes line numbers, source file names, and local variable names.
- **Logging Stripping**: `-assumenosideeffects` removes all `android.util.Log` and `System.out.println` calls from release builds to prevent accidental credential leakage.
- **Preserved Symbols**: Only JNI native exports and React Native package interfaces are retained.

---

## 6. Anti-Leak Redaction Filter

The `SanitizedLogger` and `redactSensitiveData()` utilities prevent sensitive keys or hashes from appearing in logs or error messages:
- Detects and replaces 64-character continuous hex strings with `[REDACTED_256BIT_SECRET]`.
- Detects and replaces 32-character continuous hex strings with `[REDACTED_128BIT_BUFFER]`.
- Detects and replaces Base64 secret strings with `[REDACTED_ENCODED_PAYLOAD]`.
