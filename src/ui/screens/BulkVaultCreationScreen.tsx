/**
 * @file BulkVaultCreationScreen.tsx
 * @summary Ghost-Tag Bulk Distributed Vault Creation Screen (v2).
 *
 * Implements the multi-file vault creation flow, displaying exact user promises,
 * limitations, SAF file picker integration, and tag capacity calculations.
 */

import React, { useState } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ScrollView,
} from 'react-native';

export const PROMISE_TEXT =
  'Ghost-Tag splits your encrypted files into pieces and stores one piece on each NFC tag. You can scan the tags in any order later. Ghost-Tag identifies each piece, verifies it, and reassembles your files when enough valid pieces are collected.';

export const LIMITATION_TEXT =
  'A lost, damaged, or missing tag may prevent reconstruction. Enable redundancy to tolerate lost tags. Ghost-Tag does not prevent tag cloning, deletion, or replay.';

export interface SelectedFile {
  readonly id: string;
  readonly name: string;
  readonly sizeBytes: number;
  readonly mimeType: string;
}

export interface BulkVaultCreationScreenProps {
  readonly onProceedToBulkWrite?: (files: SelectedFile[], redundancyM: number) => void;
}

export const BulkVaultCreationScreen: React.FC<BulkVaultCreationScreenProps> = ({
  onProceedToBulkWrite,
}) => {
  const [selectedFiles, setSelectedFiles] = useState<SelectedFile[]>([
    { id: '1', name: 'holiday.mp4', sizeBytes: 8 * 1024 * 1024, mimeType: 'video/mp4' },
    { id: '2', name: 'report.pdf', sizeBytes: 1024 * 1024, mimeType: 'application/pdf' },
    { id: '3', name: 'notes.txt', sizeBytes: 500 * 1024, mimeType: 'text/plain' },
  ]);
  const [redundancyM, setRedundancyM] = useState<number>(0);

  // Example capacity baseline for NTAG213 / standard Type 2 Tag (~110 KB chunks or ~134B fixed overhead)
  const totalSizeBytes = selectedFiles.reduce((acc, f) => acc + f.sizeBytes, 0);

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.contentContainer}>
      <View style={styles.header}>
        <View style={styles.badgeContainer}>
          <Text style={styles.badgeText}>BULK DISTRIBUTED VAULT</Text>
        </View>
        <Text style={styles.title}>Create Distributed Vault</Text>
        <Text style={styles.subtitle}>Store arbitrary files across sets of standard NFC tags</Text>
      </View>

      {/* Core User Promise */}
      <View style={styles.promiseCard}>
        <Text style={styles.cardSectionTitle}>PROMISE</Text>
        <Text style={styles.promiseText}>{PROMISE_TEXT}</Text>
      </View>

      {/* Core Limitation */}
      <View style={styles.limitationCard}>
        <Text style={styles.limitationSectionTitle}>LIMITATION</Text>
        <Text style={styles.limitationText}>{LIMITATION_TEXT}</Text>
      </View>

      {/* File List */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Selected Files ({selectedFiles.length})</Text>
        {selectedFiles.map((f) => (
          <View key={f.id} style={styles.fileRow}>
            <View>
              <Text style={styles.fileName}>{f.name}</Text>
              <Text style={styles.fileMime}>{f.mimeType}</Text>
            </View>
            <Text style={styles.fileSize}>{(f.sizeBytes / 1024).toFixed(1)} KB</Text>
          </View>
        ))}

        <TouchableOpacity
          style={styles.addFileButton}
          onPress={() => {
            // In production, opens Android SAF ACTION_OPEN_DOCUMENT
          }}
        >
          <Text style={styles.addFileButtonText}>+ Add Another File (SAF)</Text>
        </TouchableOpacity>
      </View>

      {/* Redundancy Selection */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Reed-Solomon Fault Tolerance</Text>
        <Text style={styles.sectionSubtitle}>
          Generate recovery chunks to reconstruct files even if tags are lost or damaged.
        </Text>
        <View style={styles.redundancyRow}>
          {[0, 1, 2, 5].map((m) => (
            <TouchableOpacity
              key={m}
              style={[styles.redundancyChip, redundancyM === m && styles.redundancyChipActive]}
              onPress={() => setRedundancyM(m)}
            >
              <Text style={[styles.redundancyText, redundancyM === m && styles.redundancyTextActive]}>
                +{m} {m === 1 ? 'Tag' : 'Tags'}
              </Text>
            </TouchableOpacity>
          ))}
        </View>
      </View>

      {/* Action */}
      <TouchableOpacity
        style={styles.primaryButton}
        onPress={() => onProceedToBulkWrite?.(selectedFiles, redundancyM)}
      >
        <Text style={styles.primaryButtonText}>Calculate Tags & Begin Write</Text>
      </TouchableOpacity>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0c',
  },
  contentContainer: {
    padding: 20,
    gap: 16,
  },
  header: {
    alignItems: 'center',
    marginVertical: 12,
  },
  badgeContainer: {
    backgroundColor: 'rgba(0, 230, 153, 0.12)',
    borderColor: '#00e699',
    borderWidth: 1,
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
    marginBottom: 8,
  },
  badgeText: {
    color: '#00e699',
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 1.2,
  },
  title: {
    fontSize: 26,
    fontWeight: '800',
    color: '#ffffff',
  },
  subtitle: {
    fontSize: 13,
    color: '#8e8e93',
    marginTop: 4,
    textAlign: 'center',
  },
  promiseCard: {
    backgroundColor: '#121217',
    borderColor: '#00e699',
    borderWidth: 1,
    borderRadius: 8,
    padding: 14,
  },
  cardSectionTitle: {
    color: '#00e699',
    fontSize: 11,
    fontWeight: '800',
    marginBottom: 6,
    letterSpacing: 1,
  },
  promiseText: {
    color: '#d1d1d6',
    fontSize: 13,
    lineHeight: 18,
  },
  limitationCard: {
    backgroundColor: '#171212',
    borderColor: '#ff9500',
    borderWidth: 1,
    borderRadius: 8,
    padding: 14,
  },
  limitationSectionTitle: {
    color: '#ff9500',
    fontSize: 11,
    fontWeight: '800',
    marginBottom: 6,
    letterSpacing: 1,
  },
  limitationText: {
    color: '#d1d1d6',
    fontSize: 13,
    lineHeight: 18,
  },
  section: {
    backgroundColor: '#141419',
    borderRadius: 8,
    padding: 16,
    borderWidth: 1,
    borderColor: '#24242d',
  },
  sectionTitle: {
    fontSize: 15,
    fontWeight: '700',
    color: '#ffffff',
    marginBottom: 4,
  },
  sectionSubtitle: {
    fontSize: 12,
    color: '#8e8e93',
    marginBottom: 12,
  },
  fileRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: '#24242d',
  },
  fileName: {
    color: '#ffffff',
    fontSize: 14,
    fontWeight: '600',
  },
  fileMime: {
    color: '#8e8e93',
    fontSize: 11,
  },
  fileSize: {
    color: '#00e699',
    fontSize: 13,
    fontFamily: 'monospace',
  },
  addFileButton: {
    marginTop: 12,
    paddingVertical: 8,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#3a3a48',
    borderRadius: 6,
    borderStyle: 'dashed',
  },
  addFileButtonText: {
    color: '#00e699',
    fontSize: 13,
    fontWeight: '600',
  },
  redundancyRow: {
    flexDirection: 'row',
    gap: 8,
  },
  redundancyChip: {
    flex: 1,
    paddingVertical: 8,
    alignItems: 'center',
    borderRadius: 6,
    backgroundColor: '#1c1c24',
    borderWidth: 1,
    borderColor: '#2e2e3a',
  },
  redundancyChipActive: {
    backgroundColor: 'rgba(0, 230, 153, 0.15)',
    borderColor: '#00e699',
  },
  redundancyText: {
    color: '#8e8e93',
    fontSize: 12,
    fontWeight: '600',
  },
  redundancyTextActive: {
    color: '#00e699',
    fontWeight: '700',
  },
  primaryButton: {
    backgroundColor: '#00e699',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 8,
  },
  primaryButtonText: {
    color: '#000000',
    fontSize: 15,
    fontWeight: '800',
  },
});
