/**
 * @file diagnosticsExporter.ts
 * @summary Export-Safe System Diagnostics and Audit Log Serializer.
 *
 * Sanitizes and exports operational logs, tag capabilities, and vault health statistics.
 *
 * Strict Privacy Invariants:
 * - NO plaintext payloads
 * - NO master passphrases
 * - NO recovery secrets or BIP39 phrases
 * - NO Key Encryption Keys (KEK) or Data Encryption Keys (DEK)
 * - NO raw ciphertext blobs
 * - NO physical location data or clipboard captures
 * - All Key IDs truncated for diagnostic correlation without exposure
 */

import { VaultManager } from '../vault/vaultManager';
import { TagInfo, TagIdentification } from '../nfc/tagInfo';
import { GhostNfcManager, NfcTag } from '../nfc/nfcManager';
import { AuditEntry } from '../contracts/vault';

export interface DiagnosticsReport {
  readonly timestamp: string;
  readonly appVersion: string;
  readonly platform: 'android';
  readonly nfcStatus: {
    readonly isSupported: boolean;
    readonly isEnabled: boolean;
  };
  readonly vaultStatus: {
    readonly isInitialized: boolean;
    readonly isUnlocked: boolean;
    readonly totalKeyCount?: number;
    readonly activeKeyCount?: number;
    readonly autoLockTimeoutMs?: number;
  };
  readonly inspectedTag?: {
    readonly family: string;
    readonly isSupported: boolean;
    readonly isWritable: boolean;
    readonly totalCapacityBytes: number;
    readonly usablePlaintextSpaceBytes: number;
  };
  readonly recentAuditEntries: readonly SanitizedAuditEntry[];
}

export interface SanitizedAuditEntry {
  readonly eventId: string;
  readonly eventType: string;
  readonly timestamp: number;
  readonly resultCode: string;
  readonly tagFamily?: string;
  readonly keyIdTruncated?: string;
  readonly envelopeVersion?: number;
  readonly errorCode?: string;
}

export class DiagnosticsExporter {
  private readonly vaultManager: VaultManager;
  private readonly nfcManager: GhostNfcManager;
  private readonly tagInfoHelper: TagInfo;

  constructor(
    vaultManager: VaultManager,
    nfcManager = new GhostNfcManager(),
    tagInfoHelper = new TagInfo()
  ) {
    this.vaultManager = vaultManager;
    this.nfcManager = nfcManager;
    this.tagInfoHelper = tagInfoHelper;
  }

  /**
   * Generates a fully scrubbed, export-safe JSON diagnostics report.
   */
  public async generateReport(inspectedTag?: NfcTag): Promise<DiagnosticsReport> {
    const isNfcSupported = await this.nfcManager.isNfcSupported();
    const isNfcEnabled = await this.nfcManager.isNfcEnabled();

    const isInitialized = await this.vaultManager.isVaultInitialized();
    const session = this.vaultManager.getActiveSession();
    const isUnlocked = session ? session.isUnlocked : false;

    let totalKeyCount: number | undefined;
    let activeKeyCount: number | undefined;
    let autoLockTimeoutMs: number | undefined;

    if (isInitialized) {
      try {
        const metadata = await this.vaultManager.getVaultMetadata();
        totalKeyCount = metadata.wrappedDekCount;
        activeKeyCount = metadata.wrappedDekCount;
      } catch {
        // Vault may be locked or reading metadata failed
      }
    }

    if (session) {
      autoLockTimeoutMs = session.getAutoLockTimeout();
    }

    let tagDiagnostics: DiagnosticsReport['inspectedTag'];
    if (inspectedTag) {
      const identification = this.tagInfoHelper.identifyTag(inspectedTag);
      const capacity = this.tagInfoHelper.getCapacity(inspectedTag);
      const isWritable = this.tagInfoHelper.isTagWritable(inspectedTag);
      const usableSpace = this.tagInfoHelper.calculateAvailableSpace(inspectedTag);

      tagDiagnostics = {
        family: identification.family,
        isSupported: identification.isSupported,
        isWritable,
        totalCapacityBytes: capacity.rawUserMemoryBytes,
        usablePlaintextSpaceBytes: usableSpace,
      };
    }

    let sanitizedEntries: SanitizedAuditEntry[] = [];
    try {
      const auditLog = this.vaultManager.getAuditLog();
      const rawEntries = await auditLog.getEvents({ limit: 50 });
      sanitizedEntries = rawEntries.map((e) => this.sanitizeEntry(e));
    } catch {
      // Ignore audit access errors during uninitialized state
    }

    return {
      timestamp: new Date().toISOString(),
      appVersion: '1.0.0',
      platform: 'android',
      nfcStatus: {
        isSupported: isNfcSupported,
        isEnabled: isNfcEnabled,
      },
      vaultStatus: {
        isInitialized,
        isUnlocked,
        totalKeyCount,
        activeKeyCount,
        autoLockTimeoutMs,
      },
      inspectedTag: tagDiagnostics,
      recentAuditEntries: sanitizedEntries,
    };
  }

  /**
   * Sanitizes individual audit records to strip any forbidden values.
   */
  private sanitizeEntry(entry: AuditEntry): SanitizedAuditEntry {
    return {
      eventId: entry.eventId,
      eventType: entry.eventType,
      timestamp: entry.timestamp,
      resultCode: String(entry.resultCode),
      tagFamily: entry.tagFamily ?? undefined,
      keyIdTruncated: entry.keyId ? `${entry.keyId.slice(0, 8)}...` : undefined,
      envelopeVersion: entry.envelopeVersion ?? undefined,
      errorCode: entry.errorCode ?? undefined,
    };
  }
}
