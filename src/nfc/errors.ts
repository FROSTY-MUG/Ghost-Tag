/**
 * @file errors.ts
 * @summary NFC Hardware Abstraction Layer Error Mapping and Factory Functions.
 *
 * Maps low-level exceptions from react-native-nfc-manager, Android NFC subsystem,
 * and transport tear events into strongly-typed GhostTagError instances conforming
 * to the Ghost-Tag canonical error registry.
 */

import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { NfcError } from 'react-native-nfc-manager';

/**
 * Maps an arbitrary caught error or react-native-nfc-manager exception to a typed GhostTagError.
 *
 * Handles:
 * - Existing GhostTagError instances (returned directly)
 * - Known NfcError class hierarchy from react-native-nfc-manager
 * - Android native string exception messages
 * - Standard JavaScript Error and unknown objects
 *
 * @param error The caught error or exception.
 * @returns A canonical GhostTagError instance.
 */
export function mapNfcError(error: unknown): GhostTagError {
  if (error instanceof GhostTagError) {
    return error;
  }

  // Handle react-native-nfc-manager typed exceptions
  if (NfcError?.RadioDisabled && error instanceof NfcError.RadioDisabled) {
    return createNfcDisabledError('Device NFC radio is turned off.', error);
  }

  if (NfcError?.UnsupportedFeature && error instanceof NfcError.UnsupportedFeature) {
    return createNfcUnsupportedError('NFC feature or technology is unsupported.', error);
  }

  if (NfcError?.TagConnectionLost && error instanceof NfcError.TagConnectionLost) {
    return createTagLostError('Tag connection was lost during communication.', error);
  }

  if (NfcError?.TagNotConnected && error instanceof NfcError.TagNotConnected) {
    return createTagNotDetectedError('No NFC tag was connected.', error);
  }

  if (NfcError?.UserCancel && error instanceof NfcError.UserCancel) {
    return new GhostTagError({
      code: GhostTagErrorCode.TAG_NOT_DETECTED,
      userMessage: 'NFC operation was cancelled.',
      technicalDetail: 'User or system cancelled the NFC session.',
      category: ErrorCategory.OPERATION,
      severity: ErrorSeverity.INFO,
      cause: error,
    });
  }

  if (NfcError?.Timeout && error instanceof NfcError.Timeout) {
    return new GhostTagError({
      code: GhostTagErrorCode.TAG_NOT_DETECTED,
      userMessage: 'NFC operation timed out while awaiting tag presence.',
      technicalDetail: 'NFC session timed out without completing operation.',
      category: ErrorCategory.NFC,
      severity: ErrorSeverity.WARNING,
      cause: error,
    });
  }

  if (NfcError?.TagNotWritable && error instanceof NfcError.TagNotWritable) {
    return createTagReadOnlyError('Tag is configured as read-only or hardware locked.', error);
  }

  if (NfcError?.TagSizeTooSmall && error instanceof NfcError.TagSizeTooSmall) {
    return createTagCapacityInsufficientError('Payload size exceeds tag memory capacity.', error);
  }

  if (NfcError?.TagUpdateFailure && error instanceof NfcError.TagUpdateFailure) {
    return createTagWriteFailedError('Low-level tag write update failure.', error);
  }

  if (NfcError?.FirstNdefInvalid && error instanceof NfcError.FirstNdefInvalid) {
    return createTagNotNdefError('NDEF container is missing or corrupted.', error);
  }

  // Inspect error message strings from Android native bridge or standard Error objects
  const rawMessage =
    typeof error === 'string'
      ? error
      : error instanceof Error
      ? error.message
      : String(error);

  const lower = rawMessage.toLowerCase();

  if (
    lower.includes('disabled') ||
    lower.includes('not enabled') ||
    lower.includes('turn on nfc')
  ) {
    return createNfcDisabledError(rawMessage, error);
  }

  if (
    lower.includes('unsupported') ||
    lower.includes('no nfc') ||
    lower.includes('not supported')
  ) {
    return createNfcUnsupportedError(rawMessage, error);
  }

  if (
    lower.includes('tag was lost') ||
    lower.includes('lost') ||
    lower.includes('transceive fail') ||
    lower.includes('connection lost') ||
    lower.includes('tag response error') ||
    lower.includes('ioexception')
  ) {
    return createTagLostError(rawMessage, error);
  }

  if (
    lower.includes('not connected') ||
    lower.includes('no tag') ||
    lower.includes('cancelled') ||
    lower.includes('user cancel') ||
    lower.includes('timeout')
  ) {
    return createTagNotDetectedError(rawMessage, error);
  }

  if (
    lower.includes('read only') ||
    lower.includes('readonly') ||
    lower.includes('not writable') ||
    lower.includes('write-protected')
  ) {
    return createTagReadOnlyError(rawMessage, error);
  }

  if (
    lower.includes('locked') ||
    lower.includes('password') ||
    lower.includes('auth fail')
  ) {
    return createTagLockedError(rawMessage, error);
  }

  if (
    lower.includes('capacity') ||
    lower.includes('too small') ||
    lower.includes('out of memory') ||
    lower.includes('insufficient')
  ) {
    return createTagCapacityInsufficientError(rawMessage, error);
  }

  if (
    lower.includes('not ndef') ||
    lower.includes('ndef formatable') ||
    lower.includes('invalid ndef')
  ) {
    return createTagNotNdefError(rawMessage, error);
  }

  if (
    lower.includes('unverified') ||
    lower.includes('mismatch') ||
    lower.includes('verification failed')
  ) {
    return createTagWriteUnverifiedError(rawMessage, error);
  }

  if (
    lower.includes('write') ||
    lower.includes('failed to write') ||
    lower.includes('write fail')
  ) {
    return createTagWriteFailedError(rawMessage, error);
  }

  // Fallback for unclassified NFC errors
  return new GhostTagError({
    code: GhostTagErrorCode.WRITE_FAILED,
    userMessage: 'NFC operation encountered an unexpected hardware error.',
    technicalDetail: `Unclassified NFC error: ${rawMessage}`,
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.ERROR,
    cause: error,
  });
}

/**
 * Creates a GhostTagError for NFC_DISABLED.
 */
export function createNfcDisabledError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.NFC_DISABLED,
    userMessage: 'NFC is turned off. Please enable NFC in your device settings.',
    technicalDetail: detail ?? 'Host device NFC controller is disabled in system settings.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.WARNING,
    cause,
  });
}

/**
 * Creates a GhostTagError for NFC_UNSUPPORTED.
 */
export function createNfcUnsupportedError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.NFC_UNSUPPORTED,
    userMessage: 'NFC hardware is not supported or available on this device.',
    technicalDetail: detail ?? 'Host device does not possess compatible NFC hardware transceiver.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.FATAL,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_NOT_DETECTED.
 */
export function createTagNotDetectedError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_NOT_DETECTED,
    userMessage: 'No NFC tag was detected. Please hold the tag firmly against the device.',
    technicalDetail: detail ?? 'No compatible NFC tag discovered within the antenna RF field.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.INFO,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_LOST.
 */
export function createTagLostError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_LOST,
    userMessage: 'Tag was moved away too quickly. Please hold the tag steady against the device.',
    technicalDetail: detail ?? 'RF link terminated prematurely during active transmission.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.WARNING,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_UNSUPPORTED.
 */
export function createTagUnsupportedError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_UNSUPPORTED,
    userMessage: 'This tag type is not supported. Ghost-Tag requires NFC Forum Type 2 tags (e.g. NTAG213/215/216).',
    technicalDetail: detail ?? 'Detected tag hardware is not an approved Type 2 Tag family.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.ERROR,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_NOT_NDEF.
 */
export function createTagNotNdefError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_NOT_NDEF,
    userMessage: 'Tag does not contain valid NDEF records.',
    technicalDetail: detail ?? 'Tag does not contain a valid NDEF container or records.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.ERROR,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_READ_ONLY.
 */
export function createTagReadOnlyError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_READ_ONLY,
    userMessage: 'This tag is permanently locked or configured as read-only.',
    technicalDetail: detail ?? 'Static or dynamic hardware lock bits prevent write operations.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.ERROR,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_LOCKED.
 */
export function createTagLockedError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_LOCKED,
    userMessage: 'This tag is password protected or locked.',
    technicalDetail: detail ?? 'Tag access is protected by vendor password authentication.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.ERROR,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_CAPACITY_INSUFFICIENT.
 */
export function createTagCapacityInsufficientError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_CAPACITY_INSUFFICIENT,
    userMessage: 'Tag capacity is too small for this payload and required envelope overhead.',
    technicalDetail: detail ?? 'Usable memory is smaller than envelope overhead plus ciphertext payload.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.ERROR,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_WRITE_FAILED.
 */
export function createTagWriteFailedError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_WRITE_FAILED,
    userMessage: 'Failed to write data to tag. Please hold tag steady and try again.',
    technicalDetail: detail ?? 'Low-level command error executing write pages on NFC tag.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.ERROR,
    cause,
  });
}

/**
 * Creates a GhostTagError for TAG_WRITE_UNVERIFIED.
 */
export function createTagWriteUnverifiedError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.TAG_WRITE_UNVERIFIED,
    userMessage: 'Tag write completed but verification failed. Data on tag was corrupted.',
    technicalDetail: detail ?? 'Read-back verification comparison did not match written envelope data.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.CRITICAL,
    cause,
  });
}

/**
 * Creates a GhostTagError for WIPE_PARTIAL.
 */
export function createWipePartialError(detail?: string, cause?: unknown): GhostTagError {
  return new GhostTagError({
    code: GhostTagErrorCode.WIPE_PARTIAL,
    userMessage: 'Tag wipe was interrupted and only partially completed. Sensitive data remnants may remain.',
    technicalDetail: detail ?? 'Sanitization aborted prior to completing all overwrite passes.',
    category: ErrorCategory.NFC,
    severity: ErrorSeverity.CRITICAL,
    cause,
  });
}
