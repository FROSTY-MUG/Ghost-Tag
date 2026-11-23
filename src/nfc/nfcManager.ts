/**
 * @file nfcManager.ts
 * @summary NFC Subsystem Lifecycle and Android Foreground Dispatch Management.
 *
 * Encapsulates react-native-nfc-manager with comprehensive lifecycle management,
 * Android foreground dispatch handling, hardware state monitoring, typed error mapping,
 * and operation timeout guarantees.
 */

import { Platform } from 'react-native';
import NfcManager, {
  NfcEvents,
  NfcTech,
  RegisterTagEventOpts,
} from 'react-native-nfc-manager';
import { NfcTag } from './tagInfo';
import {
  mapNfcError,
  createNfcDisabledError,
  createNfcUnsupportedError,
} from './errors';
import { GhostTagError, GhostTagErrorCode, ErrorCategory, ErrorSeverity } from '../contracts/errors';
export type { NfcTag } from './tagInfo';

/**
 * Discovery callback invoked when an NFC tag enters the antenna RF field.
 */
export type TagCallback = (tag: NfcTag) => void | Promise<void>;

/**
 * State change callback invoked when host NFC controller is enabled or disabled.
 */
export type StateChangeCallback = (enabled: boolean) => void;

/**
 * Options configuration for foreground listening dispatch.
 */
export interface StartListeningOptions extends RegisterTagEventOpts {
  /**
   * Optional timeout in milliseconds. If specified, listening is automatically
   * stopped if no tag is discovered within this duration.
   */
  readonly timeoutMs?: number;
  /**
   * Callback invoked if the timeout expires prior to tag discovery.
   */
  readonly onTimeout?: () => void;
}

/**
 * NFC hardware abstraction manager for Android foreground dispatch and lifecycle control.
 */
export class GhostNfcManager {
  private initialized: boolean = false;
  private listening: boolean = false;
  private activeCallback: TagCallback | null = null;
  private timeoutTimer: ReturnType<typeof setTimeout> | null = null;
  private stateChangeListeners: Set<StateChangeCallback> = new Set();

  /**
   * Initializes the native NFC subsystem. Safe to call multiple times (idempotent).
   *
   * @throws GhostTagError if native initialization fails.
   */
  public async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      await NfcManager.start();
      this.initialized = true;

      // Register Android state changed listener
      try {
        NfcManager.setEventListener(NfcEvents.StateChanged, (evt: { state: string }) => {
          const isEnabled = evt?.state === 'on';
          for (const listener of this.stateChangeListeners) {
            try {
              listener(isEnabled);
            } catch {
              // Ignore listener errors
            }
          }
        });
      } catch {
        // Platform might not support StateChanged event
      }
    } catch (error) {
      throw mapNfcError(error);
    }
  }

  /**
   * Checks whether the device hardware includes an NFC controller.
   *
   * @returns True if NFC is supported by the device.
   */
  public async isNfcSupported(): Promise<boolean> {
    try {
      await this.initialize();
      const supported = await NfcManager.isSupported();
      return Boolean(supported);
    } catch {
      return false;
    }
  }

  /**
   * Checks whether the device NFC transceiver is currently switched ON in system settings.
   *
   * @returns True if NFC is currently enabled and ready.
   */
  public async isNfcEnabled(): Promise<boolean> {
    try {
      await this.initialize();
      const enabled = await NfcManager.isEnabled();
      return Boolean(enabled);
    } catch {
      return false;
    }
  }

  /**
   * Starts listening for NFC tags using Android foreground dispatch.
   *
   * Verifies that NFC is supported and enabled prior to arming the receiver.
   * When a tag is tapped, the provided `onTagDiscovered` callback is executed.
   *
   * @param onTagDiscovered Callback receiving the detected NfcTag.
   * @param options Optional configuration including reader mode flags and timeout.
   * @throws GhostTagError if NFC is unsupported, disabled, or dispatch registration fails.
   */
  public async startListening(
    onTagDiscovered: TagCallback,
    options?: StartListeningOptions
  ): Promise<void> {
    await this.initialize();

    const supported = await this.isNfcSupported();
    if (!supported) {
      throw createNfcUnsupportedError('Device does not support NFC operations.');
    }

    const enabled = await this.isNfcEnabled();
    if (!enabled) {
      throw createNfcDisabledError('NFC is currently disabled. Please enable it in system settings.');
    }

    // Stop existing listener if active
    if (this.listening) {
      await this.stopListening();
    }

    this.activeCallback = onTagDiscovered;

    try {
      NfcManager.setEventListener(NfcEvents.DiscoverTag, async (tag: NfcTag) => {
        this.clearTimeoutTimer();
        if (this.activeCallback) {
          try {
            await this.activeCallback(tag);
          } catch (_callbackErr) {
            // Callback errors are handled within the callback; do not crash listener
          }
        }
      });

      const { timeoutMs, onTimeout, ...registerOpts } = options ?? {};

      if (Platform.OS === 'ios') {
        // iOS: react-native-nfc-manager surfaces NDEF discovery as DiscoverTag
        // events while an NFCNDEFReaderSession is active. Begin the session by
        // requesting the NDEF technology; tags surface via the listener above.
        // CoreNFC is read-oriented: iOS discovers tags that support NDEF reading,
        // and Ghost envelope validation happens on read.
        await NfcManager.requestTechnology(NfcTech.Ndef);
      } else {
        // Android: Android foreground dispatch registration
        await NfcManager.registerTagEvent(registerOpts);
      }

      this.listening = true;

      if (timeoutMs && timeoutMs > 0) {
        this.timeoutTimer = setTimeout(async () => {
          await this.stopListening();
          if (onTimeout) {
            onTimeout();
          }
        }, timeoutMs);
      }
    } catch (error) {
      this.listening = false;
      this.activeCallback = null;
      this.clearTimeoutTimer();
      throw mapNfcError(error);
    }
  }

  /**
   * Stops listening for NFC tags and disarms the foreground dispatch system.
   */
  public async stopListening(): Promise<void> {
    this.clearTimeoutTimer();
    this.activeCallback = null;

    if (!this.listening) {
      return;
    }

    try {
      NfcManager.setEventListener(NfcEvents.DiscoverTag, null);
      if (Platform.OS === 'ios') {
        // iOS: invalidate the active NFCNDEFReaderSession
        await NfcManager.cancelTechnologyRequest();
      } else {
        // Android: unregister foreground dispatch
        await NfcManager.unregisterTagEvent();
      }
    } catch (_error) {
      // Ignore unregister errors during teardown
    } finally {
      this.listening = false;
    }
  }

  /**
   * Subscribes to NFC state transitions (enabled / disabled by user in system settings).
   *
   * @param listener Callback invoked with true when enabled, false when disabled.
   * @returns Unsubscribe cleanup function.
   */
  public onStateChanged(listener: StateChangeCallback): () => void {
    this.stateChangeListeners.add(listener);
    return () => {
      this.stateChangeListeners.delete(listener);
    };
  }

  /**
   * Opens the host operating system's NFC settings screen.
   *
   * @returns Promise resolving to true if settings activity opened successfully.
   */
  public async goToSettings(): Promise<boolean> {
    try {
      return await NfcManager.goToNfcSetting();
    } catch {
      return false;
    }
  }

  /**
   * Executes an asynchronous NFC operation bounded by a strict timeout.
   *
   * @param operation The async operation promise.
   * @param timeoutMs Timeout in milliseconds.
   * @param operationName Descriptive label for diagnostic reporting.
   * @returns Resolves with the operation result, or rejects with a TAG_NOT_DETECTED GhostTagError.
   */
  public async withTimeout<T>(
    operation: Promise<T>,
    timeoutMs: number,
    operationName: string = 'NFC operation'
  ): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | null = null;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(
          new GhostTagError({
            code: GhostTagErrorCode.TAG_NOT_DETECTED,
            userMessage: `${operationName} timed out. Please try again.`,
            technicalDetail: `${operationName} exceeded deadline of ${timeoutMs}ms without completion.`,
            category: ErrorCategory.NFC,
            severity: ErrorSeverity.WARNING,
          })
        );
      }, timeoutMs);
    });

    try {
      return await Promise.race([operation, timeoutPromise]);
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  }

  /**
   * Releases all listeners, cancels dispatch, and resets manager state.
   */
  public dispose(): void {
    this.stopListening().catch(() => {});
    try {
      NfcManager.setEventListener(NfcEvents.StateChanged, null);
    } catch {
      // Ignore cleanup error
    }
    this.stateChangeListeners.clear();
    this.initialized = false;
    this.listening = false;
    this.activeCallback = null;
    this.clearTimeoutTimer();
  }

  private clearTimeoutTimer(): void {
    if (this.timeoutTimer) {
      clearTimeout(this.timeoutTimer);
      this.timeoutTimer = null;
    }
  }
}

/**
 * Shared singleton instance of GhostNfcManager.
 */
export const ghostNfcManager = new GhostNfcManager();
