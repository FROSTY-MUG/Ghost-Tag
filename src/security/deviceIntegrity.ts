/**
 * @file deviceIntegrity.ts
 * @summary Device Integrity Coordinator and Anti-Tamper Enforcement.
 *
 * Interfaces with the native Android C++ security library (libghosttag_security.so)
 * and Kotlin security bridge to ensure that Ghost-Tag only operates in an untampered,
 * secure runtime environment.
 *
 * Security Directives:
 * - Fail-Closed: If any integrity check fails (debugger attached, Frida/Xposed hooking,
 *   root escalation, or signature mismatch), the app immediately halts sensitive operations
 *   and zeroizes all in-memory keys.
 * - Anti-Debugging: Detects ptrace attachment and TracerPid.
 * - Anti-Hooking: Detects Frida agent, gadget, and Xposed hooks.
 * - Secure Window: Verifies Android FLAG_SECURE status to block screen capture.
 */

import { NativeModules } from 'react-native';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { secureWipeBuffers } from './secureWipe';

/**
 * Diagnostic report of host device integrity status.
 */
export interface DeviceIntegrityStatus {
  /** True if the environment meets all security criteria; false if compromised. */
  readonly isSecure: boolean;
  /** True if an active debugger (GDB, LLDB, JDWP) is attached to the process. */
  readonly isDebuggerActive: boolean;
  /** True if dynamic binary instrumentation (Frida, Xposed) is detected. */
  readonly isHooked: boolean;
  /** True if root binaries, Magisk, or superuser privileges are detected. */
  readonly isRooted: boolean;
  /** True if running inside an untrusted hardware emulator. */
  readonly isEmulator: boolean;
  /** True if APK release signature matches expected official certificate. */
  readonly isSignatureValid: boolean;
  /** Array of specific compromise flags or indicator strings. */
  readonly tamperIndicators: readonly string[];
}

/** Interface of the native Android security module. */
interface GhostTagSecurityNativeModule {
  checkDeviceIntegrity(): Promise<DeviceIntegrityStatus>;
  enableSecureWindow(): Promise<boolean>;
  disableSecureWindow(): Promise<boolean>;
  wipeNativeMemory(): Promise<boolean>;
  isDebuggerActive(): Promise<boolean>;
  isHooked(): Promise<boolean>;
  isRooted(): Promise<boolean>;
}

const NativeSecurity: GhostTagSecurityNativeModule | undefined =
  NativeModules?.GhostTagSecurity;

/** Test mock override for unit testing in non-Android environments. */
let testIntegrityOverride: DeviceIntegrityStatus | null = null;

/**
 * Sets a custom test integrity status for unit test scenarios.
 *
 * @param override Custom integrity status or null to reset.
 */
export function setTestIntegrityOverride(
  override: DeviceIntegrityStatus | null
): void {
  testIntegrityOverride = override;
}

/**
 * Queries the native security subsystem for the comprehensive device integrity status.
 *
 * In production Android environments, this delegates to the C++ native layer
 * via JNI. In simulated/test environments, it returns standard safe defaults
 * unless overridden.
 *
 * @returns Comprehensive DeviceIntegrityStatus report.
 */
export async function checkDeviceIntegrity(): Promise<DeviceIntegrityStatus> {
  if (testIntegrityOverride !== null) {
    return testIntegrityOverride;
  }

  if (NativeSecurity && typeof NativeSecurity.checkDeviceIntegrity === 'function') {
    try {
      return await NativeSecurity.checkDeviceIntegrity();
    } catch {
      // If native check throws, fail-closed
      return {
        isSecure: false,
        isDebuggerActive: false,
        isHooked: false,
        isRooted: false,
        isEmulator: false,
        isSignatureValid: false,
        tamperIndicators: ['NATIVE_INTEGRITY_CHECK_EXCEPTION'],
      };
    }
  }

  // Fallback in Node.js test environment: check for debugger flags
  const proc = (globalThis as any).process;
  const isNodeDebuggerActive =
    typeof proc !== 'undefined' &&
    (proc.execArgv?.some((arg: string) => arg.includes('--inspect')) ||
      typeof (globalThis as any).v8debug !== 'undefined');

  return {
    isSecure: !isNodeDebuggerActive,
    isDebuggerActive: !!isNodeDebuggerActive,
    isHooked: false,
    isRooted: false,
    isEmulator: false,
    isSignatureValid: true,
    tamperIndicators: isNodeDebuggerActive ? ['DEBUGGER_ATTACHED'] : [],
  };
}

/**
 * Enforces strict device integrity.
 *
 * If any compromise is detected (debugger, hooking, root, or tampering),
 * this function immediately scrubs sensitive memory buffers and throws
 * a fatal GhostTagError.
 *
 * @param buffersToWipeOnFailure Optional list of sensitive buffers to zeroize upon failure.
 * @throws {GhostTagError} If the runtime environment is compromised.
 */
export async function assertDeviceIntegrity(
  ...buffersToWipeOnFailure: (Uint8Array | null | undefined)[]
): Promise<void> {
  const status = await checkDeviceIntegrity();

  if (!status.isSecure) {
    // Panic wipe: immediately overwrite all provided sensitive buffers
    secureWipeBuffers(...buffersToWipeOnFailure);

    // Call native secure wipe if available
    if (NativeSecurity && typeof NativeSecurity.wipeNativeMemory === 'function') {
      try {
        await NativeSecurity.wipeNativeMemory();
      } catch {
        // Best effort native wipe
      }
    }

    const primaryCause = status.isDebuggerActive
      ? 'Debugger detected'
      : status.isHooked
      ? 'Dynamic instrumentation (Frida/Xposed) detected'
      : status.isRooted
      ? 'Root privileges detected'
      : 'Device integrity check failed';

    const indicators = status.tamperIndicators.join(', ');

    throw new GhostTagError({
      code: status.isDebuggerActive
        ? GhostTagErrorCode.DEBUGGER_DETECTED
        : status.isHooked
        ? GhostTagErrorCode.HOOKING_DETECTED
        : status.isRooted
        ? GhostTagErrorCode.ROOT_DETECTED
        : GhostTagErrorCode.DEVICE_INTEGRITY_COMPROMISED,
      userMessage: `Security violation: ${primaryCause}. Vault operations halted.`,
      technicalDetail: `Integrity indicators: [${indicators}]`,
      category: ErrorCategory.SECURITY,
      severity: ErrorSeverity.FATAL,
    });
  }
}

/**
 * Activates Android FLAG_SECURE window mode to prevent screen recording,
 * screenshots, and recent-app thumbnail leakage.
 *
 * @returns True if successful or running in mock environment.
 */
export async function enforceSecureWindow(): Promise<boolean> {
  if (NativeSecurity && typeof NativeSecurity.enableSecureWindow === 'function') {
    try {
      return await NativeSecurity.enableSecureWindow();
    } catch {
      return false;
    }
  }
  return true;
}
