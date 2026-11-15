/**
 * @file deleteEntryOperation.ts
 * @summary Ghost-Tag v2.0.5 Android Entry Deletion & Safe Rewrite Engine.
 *
 * Implements the atomic delete-and-rewrite workflow for individual entries on Android:
 * 1. Decrypt local vault manifest.
 * 2. Remove selected entry.
 * 3. Re-encrypt remaining content.
 * 4. Recalculate chunk count and hashes.
 * 5. Identify affected NFC tags.
 * 6. Ask user to scan required tags.
 * 7. Rewrite affected tags.
 * 8. Read back and verify every rewritten tag.
 * 9. Mark deletion complete only after verification.
 *
 * Strict Security Invariant:
 * If a required tag is missing or damaged, abort immediately with:
 * "Cannot delete entry: required tag is missing."
 */

import { BulkVaultManifest, BulkFileRecord, TagMappingRecord } from '../contracts/bulkVault';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

export const DELETE_ENTRY_WARNING_HEADER = 'DELETE ENTRY';
export const DELETE_ENTRY_WARNING_BODY =
  'Deleting this entry requires rewriting encrypted Ghost data on the affected NFC tags.\n' +
  'This operation may fail if a tag is damaged, removed too early, or becomes unreadable.\n' +
  'Existing entries may become temporarily unavailable until the rewrite completes.';

export const CANNOT_DELETE_ENTRY_MESSAGE =
  'The NFC tag containing required encrypted data is missing or unreadable.\n' +
  'The entry cannot be safely deleted.';

export interface DeleteEntryPlan {
  readonly targetEntryName: string;
  readonly targetFileIdHex: string;
  readonly affectedTagUids: string[];
  readonly remainingFiles: BulkFileRecord[];
  readonly totalRemainingChunks: number;
}

export interface RewriteVerificationResult {
  readonly tagUidHex: string;
  readonly chunkIndex: number;
  readonly verified: boolean;
  readonly hashMatches: boolean;
}

export interface DeleteEntryExecutionResult {
  readonly success: boolean;
  readonly deletedEntryName: string;
  readonly rewrittenTagCount: number;
  readonly verifications: RewriteVerificationResult[];
  readonly updatedManifest: BulkVaultManifest;
}

/**
 * Plans the safe deletion of an individual entry by inspecting the manifest and tag mappings.
 */
export function planEntryDeletion(
  manifest: BulkVaultManifest,
  targetFileNameOrId: string
): DeleteEntryPlan {
  const targetFile = manifest.files.find(
    f =>
      f.fileName === targetFileNameOrId ||
      Array.from(f.fileId).map(b => b.toString(16).padStart(2, '0')).join('') === targetFileNameOrId
  );

  if (!targetFile) {
    throw new GhostTagError({
      code: GhostTagErrorCode.VAULT_CORRUPT,
      category: ErrorCategory.VAULT,
      severity: ErrorSeverity.ERROR,
      userMessage: `Target entry "${targetFileNameOrId}" not found in vault manifest.`,
    });
  }

  const targetFileIdHex = Array.from(targetFile.fileId)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Identify affected tags from local tag mappings
  const affectedMappings = manifest.tagMappings.filter(
    m => Array.from(m.fileId).map(b => b.toString(16).padStart(2, '0')).join('') === targetFileIdHex
  );

  const affectedTagUids = Array.from(new Set(affectedMappings.map(m => m.tagUidHex)));
  const remainingFiles = manifest.files.filter(f => f !== targetFile);
  const totalRemainingChunks = remainingFiles.reduce((acc, f) => acc + f.chunkCount, 0);

  return {
    targetEntryName: targetFile.fileName,
    targetFileIdHex,
    affectedTagUids,
    remainingFiles,
    totalRemainingChunks,
  };
}

/**
 * Validates that all tags affected by the rewrite are available and readable.
 * Throws if any required tag is missing.
 */
export function validateRequiredRewriteTags(
  plan: DeleteEntryPlan,
  presentedTagUids: string[]
): { ready: boolean; missingTags: string[] } {
  const presentedSet = new Set(presentedTagUids.map(u => u.toLowerCase()));
  const missingTags = plan.affectedTagUids.filter(uid => !presentedSet.has(uid.toLowerCase()));

  if (missingTags.length > 0) {
    throw new GhostTagError({
      code: GhostTagErrorCode.TAG_LOST,
      category: ErrorCategory.NFC,
      severity: ErrorSeverity.FATAL,
      userMessage: `CANNOT DELETE ENTRY: ${CANNOT_DELETE_ENTRY_MESSAGE} Missing tags: ${missingTags.join(', ')}`,
    });
  }

  return { ready: true, missingTags: [] };
}

/**
 * Executes the atomic entry deletion and manifest update after verified tag rewriting.
 */
export async function finalizeEntryDeletion(
  currentManifest: BulkVaultManifest,
  plan: DeleteEntryPlan,
  verifications: RewriteVerificationResult[]
): Promise<DeleteEntryExecutionResult> {
  // Ensure every affected tag has a successful read-back verification
  for (const uid of plan.affectedTagUids) {
    const v = verifications.find(item => item.tagUidHex.toLowerCase() === uid.toLowerCase());
    if (!v || !v.verified || !v.hashMatches) {
      throw new GhostTagError({
        code: GhostTagErrorCode.TAG_WRITE_UNVERIFIED,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.FATAL,
        userMessage: `Write could not be verified on tag UID: ${uid}. Deletion aborted to prevent corruption.`,
      });
    }
  }

  // Build the updated manifest with the entry safely deleted
  const updatedTagMappings: TagMappingRecord[] = currentManifest.tagMappings.filter(
    m => Array.from(m.fileId).map(b => b.toString(16).padStart(2, '0')).join('') !== plan.targetFileIdHex
  );

  const updatedManifest: BulkVaultManifest = {
    ...currentManifest,
    files: plan.remainingFiles,
    totalVaultChunks: plan.totalRemainingChunks,
    tagMappings: updatedTagMappings,
    updatedAt: Date.now(),
  };

  return {
    success: true,
    deletedEntryName: plan.targetEntryName,
    rewrittenTagCount: plan.affectedTagUids.length,
    verifications,
    updatedManifest,
  };
}
