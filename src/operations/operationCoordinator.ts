/**
 * @file operationCoordinator.ts
 * @summary Central Coordinator for Ghost-Tag Hardware, Crypto, and Storage Workflows.
 *
 * Provides a single high-level API facade consumed by the user interface,
 * tying together VaultManager, GhostNfcManager, and individual operation executors.
 */

import { VaultManager } from '../vault/vaultManager';
import { GhostNfcManager, NfcTag } from '../nfc/nfcManager';
import { TagReader } from '../nfc/tagReader';
import { TagWriter } from '../nfc/tagWriter';
import { TagWiper } from '../nfc/tagWiper';
import { TagInfo } from '../nfc/tagInfo';

import { ScanOperation, ScanResult, ScanStateCallback } from './scanOperation';
import { WriteOperation, WriteResult, WritePayloadOptions, WriteStateCallback } from './writeOperation';
import { WipeOperation, WipeResult, WipeStateCallback } from './wipeOperation';
import { VerifyOperation, VerifyOperationResult } from './verifyOperation';
import { RepairOperation, RepairOperationResult } from './repairOperation';
import { DiagnosticsExporter, DiagnosticsReport } from './diagnosticsExporter';


export type GeneralStatusListener = (statusLine: string, level?: 'info' | 'warn' | 'error' | 'success') => void;

export class OperationCoordinator {
  private readonly vaultManager: VaultManager;
  private readonly nfcManager: GhostNfcManager;
  private readonly reader: TagReader;
  private readonly writer: TagWriter;
  private readonly wiper: TagWiper;
  private readonly tagInfoHelper: TagInfo;

  private readonly scanOp: ScanOperation;
  private readonly writeOp: WriteOperation;
  private readonly wipeOp: WipeOperation;
  private readonly verifyOp: VerifyOperation;
  private readonly repairOp: RepairOperation;
  private readonly diagExporter: DiagnosticsExporter;

  private isListeningForTags = false;

  constructor(
    vaultManager: VaultManager,
    nfcManager = new GhostNfcManager(),
    reader = new TagReader(),
    writer = new TagWriter(),
    wiper = new TagWiper(),
    tagInfoHelper = new TagInfo()
  ) {
    this.vaultManager = vaultManager;
    this.nfcManager = nfcManager;
    this.reader = reader;
    this.writer = writer;
    this.wiper = wiper;
    this.tagInfoHelper = tagInfoHelper;

    this.scanOp = new ScanOperation(vaultManager, reader, tagInfoHelper);
    this.writeOp = new WriteOperation(vaultManager, writer, tagInfoHelper);
    this.wipeOp = new WipeOperation(wiper, tagInfoHelper);
    this.verifyOp = new VerifyOperation(vaultManager, reader, tagInfoHelper);
    this.repairOp = new RepairOperation(vaultManager, this.scanOp, this.writeOp);
    this.diagExporter = new DiagnosticsExporter(vaultManager, nfcManager, tagInfoHelper);
  }

  // ---------------------------------------------------------------------------
  // NFC Discovery Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Starts foreground NFC tag listening.
   */
  public async startListening(onTagDiscovered: (tag: NfcTag) => void): Promise<void> {
    if (this.isListeningForTags) {
      return;
    }
    await this.nfcManager.startListening(onTagDiscovered);
    this.isListeningForTags = true;
  }

  /**
   * Disarms foreground NFC tag listening.
   */
  public async stopListening(): Promise<void> {
    if (!this.isListeningForTags) {
      return;
    }
    await this.nfcManager.stopListening();
    this.isListeningForTags = false;
  }

  // ---------------------------------------------------------------------------
  // High-Level Workflows
  // ---------------------------------------------------------------------------

  /**
   * Scans and decrypts an envelope from a detected tag.
   */
  public async scanTag(tag: NfcTag, onStateChange?: ScanStateCallback): Promise<ScanResult> {
    return this.scanOp.execute(tag, onStateChange);
  }

  /**
   * Encrypts and writes a payload to a target tag with read-back verification.
   */
  public async writeTag(
    tag: NfcTag,
    options: WritePayloadOptions,
    onStateChange?: WriteStateCallback
  ): Promise<WriteResult> {
    return this.writeOp.execute(tag, options, onStateChange);
  }

  /**
   * Sanitizes a tag via destructive multi-pass overwrite.
   */
  public async wipeTag(tag: NfcTag, onStateChange?: WipeStateCallback): Promise<WipeResult> {
    return this.wipeOp.execute(tag, onStateChange);
  }

  /**
   * Performs non-destructive envelope inspection.
   */
  public async verifyTag(tag: NfcTag): Promise<VerifyOperationResult> {
    return this.verifyOp.execute(tag);
  }

  /**
   * Re-encrypts and rewrites an existing valid tag.
   */
  public async repairTag(tag: NfcTag, rotateKey = false): Promise<RepairOperationResult> {
    return this.repairOp.execute(tag, rotateKey);
  }

  /**
   * Exports sanitized diagnostics report.
   */
  public async exportDiagnostics(inspectedTag?: NfcTag): Promise<DiagnosticsReport> {
    return this.diagExporter.generateReport(inspectedTag);
  }

  // ---------------------------------------------------------------------------
  // Accessors
  // ---------------------------------------------------------------------------

  public getVaultManager(): VaultManager {
    return this.vaultManager;
  }

  public getNfcManager(): GhostNfcManager {
    return this.nfcManager;
  }

  public getTagInfoHelper(): TagInfo {
    return this.tagInfoHelper;
  }
}
