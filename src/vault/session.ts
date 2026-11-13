/**
 * @file session.ts
 * @summary Unlock Session Management for the Ghost-Tag Vault.
 *
 * Manages the volatile in-memory lifecycle of the Key Encryption Key (KEK).
 * Guarantees that sensitive key material is wiped (zeroized) upon session termination,
 * auto-lock timeout, or application backgrounding.
 */

import { AppState, type NativeEventSubscription } from 'react-native';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { zeroize, secureWipeBuffer } from '../crypto/secureMemory';
import { generateSecureRandom } from '../crypto/random';
import { bytesToHex } from '../crypto/keyWrap';
import { assertDeviceIntegrity } from '../security/deviceIntegrity';

/** Default session auto-lock timeout: 5 minutes in milliseconds. */
export const DEFAULT_AUTO_LOCK_TIMEOUT_MS = 5 * 60 * 1000; // 300,000 ms

/** Function signature for re-deriving the KEK during session unlock. */
export type SessionUnlockHandler = (passphrase: string) => Promise<Uint8Array>;

/**
 * Manages the lifecycle of an active unlocked vault session.
 */
export class VaultSession {
  private _isUnlocked = false;
  private readonly _sessionId: string;
  private kek: Uint8Array | null = null;
  private autoLockTimeoutMs: number = DEFAULT_AUTO_LOCK_TIMEOUT_MS;
  private timerHandle: ReturnType<typeof setTimeout> | null = null;
  private appStateSubscription: NativeEventSubscription | null = null;
  private readonly unlockHandler?: SessionUnlockHandler;
  private readonly lockListeners: Set<() => void> = new Set();

  /**
   * Constructs a new VaultSession instance.
   *
   * @param initialKek Ephemeral 32-byte KEK if session starts unlocked.
   * @param unlockHandler Optional derivation callback for subsequent unlock invocations.
   * @param autoLockTimeoutMs Optional custom auto-lock timeout in milliseconds.
   */
  constructor(
    initialKek?: Uint8Array | null,
    unlockHandler?: SessionUnlockHandler,
    autoLockTimeoutMs: number = DEFAULT_AUTO_LOCK_TIMEOUT_MS
  ) {
    this._sessionId = bytesToHex(generateSecureRandom(16));
    this.unlockHandler = unlockHandler;
    this.autoLockTimeoutMs = autoLockTimeoutMs > 0 ? autoLockTimeoutMs : DEFAULT_AUTO_LOCK_TIMEOUT_MS;

    if (initialKek && initialKek.length === 32) {
      this.kek = new Uint8Array(initialKek.length);
      this.kek.set(initialKek);
      this._isUnlocked = true;
      this.resetAutoLockTimer();
      this.registerAppStateListener();
    }
  }

  /**
   * Indicates whether the session is currently in an unlocked state with KEK present in memory.
   */
  public get isUnlocked(): boolean {
    return this._isUnlocked;
  }

  /**
   * Unique session identifier (random 128-bit hex string).
   */
  public get sessionId(): string {
    return this._sessionId;
  }

  /**
   * Unlocks the vault session with the user master passphrase.
   *
   * @param passphrase User master passphrase.
   * @throws {GhostTagError} If passphrase verification or KEK derivation fails.
   */
  public async unlock(passphrase: string): Promise<void> {
    // Enforce strict device integrity before processing any master passphrase
    await assertDeviceIntegrity();

    if (this._isUnlocked && this.kek) {
      this.resetAutoLockTimer();
      return;
    }

    if (!this.unlockHandler) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
        userMessage: 'No unlock handler configured for this session.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    try {
      const derivedKek = await this.unlockHandler(passphrase);
      if (!derivedKek || derivedKek.length !== 32) {
        throw new GhostTagError({
          code: GhostTagErrorCode.PASSPHRASE_INVALID,
          userMessage: 'Derived KEK is invalid or has incorrect length.',
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.ERROR,
        });
      }

      // If a previous KEK existed, secure wipe it before overwriting
      if (this.kek) {
        secureWipeBuffer(this.kek);
      }

      this.kek = new Uint8Array(derivedKek.length);
      this.kek.set(derivedKek);
      this._isUnlocked = true;
      this.resetAutoLockTimer();
      this.registerAppStateListener();
    } catch (err) {
      this.lock();
      if (err instanceof GhostTagError) {
        throw err;
      }
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_INVALID,
        userMessage: 'Failed to unlock vault session with provided passphrase.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
        cause: err,
      });
    }
  }

  /**
   * Locks the vault session immediately, zeroizing volatile KEK memory buffers.
   */
  public lock(): void {
    if (this.kek) {
      secureWipeBuffer(this.kek);
      this.kek = null;
    }

    this._isUnlocked = false;

    if (this.timerHandle !== null) {
      clearTimeout(this.timerHandle);
      this.timerHandle = null;
    }

    this.removeAppStateListener();

    // Notify registered lock listeners
    for (const listener of this.lockListeners) {
      try {
        listener();
      } catch {
        // Defensive: don't let listener exceptions prevent locking
      }
    }
  }

  /**
   * Retrieves the Key Encryption Key (KEK) if the session is currently unlocked.
   *
   * Security Directives:
   * - Callers MUST NOT retain the returned buffer reference in long-lived state.
   * - Any intermediate copies made by the caller MUST be zeroized after use.
   *
   * @returns Ephemeral 32-byte KEK if unlocked, or null if locked.
   */
  public getKEK(): Uint8Array | null {
    if (!this._isUnlocked || !this.kek) {
      return null;
    }
    // Return an isolated copy to prevent external mutation of the session's internal buffer
    const copy = new Uint8Array(this.kek.length);
    copy.set(this.kek);
    return copy;
  }

  /**
   * Retrieves the current auto-lock timeout interval in milliseconds.
   */
  public getAutoLockTimeout(): number {
    return this.autoLockTimeoutMs;
  }

  /**
   * Configures the auto-lock timeout interval.
   *
   * @param ms Timeout interval in milliseconds (must be positive).
   */
  public setAutoLockTimeout(ms: number): void {
    if (!Number.isFinite(ms) || ms <= 0) {
      throw new RangeError(`Auto-lock timeout must be a positive integer, received: ${ms}`);
    }
    this.autoLockTimeoutMs = ms;
    if (this._isUnlocked) {
      this.resetAutoLockTimer();
    }
  }

  /**
   * Resets the auto-lock countdown timer to the configured interval.
   */
  public resetAutoLockTimer(): void {
    if (this.timerHandle !== null) {
      clearTimeout(this.timerHandle);
      this.timerHandle = null;
    }

    if (this._isUnlocked && this.autoLockTimeoutMs > 0) {
      this.timerHandle = setTimeout(() => {
        this.lock();
      }, this.autoLockTimeoutMs);

      // In Node/test environments, allow timer to not hold the process open
      if (typeof this.timerHandle === 'object' && typeof (this.timerHandle as any).unref === 'function') {
        (this.timerHandle as any).unref();
      }
    }
  }

  /**
   * Handles React Native app state transitions.
   * Automatically locks the session when the app enters the background or becomes inactive.
   *
   * @param nextAppState Current application state ('active', 'background', or 'inactive').
   */
  public handleAppStateChange = (nextAppState: string): void => {
    if (nextAppState === 'background' || nextAppState === 'inactive') {
      this.lock();
    }
  };

  /**
   * Registers a callback invoked whenever the vault session locks.
   *
   * @param listener Callback function.
   * @returns Cleanup function to unregister the listener.
   */
  public onLock(listener: () => void): () => void {
    this.lockListeners.add(listener);
    return () => {
      this.lockListeners.delete(listener);
    };
  }

  /**
   * Registers a listener on React Native's AppState if available.
   */
  private registerAppStateListener(): void {
    if (this.appStateSubscription) {
      return;
    }
    try {
      if (AppState && typeof AppState.addEventListener === 'function') {
        this.appStateSubscription = AppState.addEventListener(
          'change',
          this.handleAppStateChange
        );
      }
    } catch {
      // AppState may be absent in Node.js test environments
    }
  }

  /**
   * Removes React Native AppState event subscription.
   */
  private removeAppStateListener(): void {
    if (this.appStateSubscription) {
      try {
        this.appStateSubscription.remove();
      } catch {
        // Safe ignore
      }
      this.appStateSubscription = null;
    }
  }
}

