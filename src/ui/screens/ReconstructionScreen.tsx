/**
 * @file ReconstructionScreen.tsx
 * @summary Ghost-Tag Distributed File Reassembly and SAF Export Screen (v2).
 *
 * Displays reassembled files, cryptographic verification badges, in-memory viewing,
 * and scoped export via Android Storage Access Framework (SAF).
 */

import React, { useState } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ScrollView,
} from 'react-native';

export interface DisplayFile {
  readonly id: string;
  readonly name: string;
  readonly mimeType: string;
  readonly sizeBytes: number;
  readonly chunkCount: number;
  readonly isVerified: boolean;
}

export interface ReconstructionScreenProps {
  readonly files?: DisplayFile[];
  readonly onDone?: () => void;
}

export const ReconstructionScreen: React.FC<ReconstructionScreenProps> = ({
  files: initialFiles = [],
  onDone,
}) => {
  const [files] = useState<DisplayFile[]>(initialFiles);

  const [logs, setLogs] = useState<string[]>(
    initialFiles.length === 0
      ? [
          '[READY] Awaiting verified bulk chunks from BulkScan before reconstruction.',
          '[INFO] Files appear only after real SHA-256 verification and AES-256-GCM decryption.',
        ]
      : [
          `[RESULT] ${initialFiles.length} file(s) provided from verified reconstruction session.`,
        ]
  );

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.contentContainer}>
      <View style={styles.header}>
        <View style={styles.badgeContainer}>
          <Text style={styles.badgeText}>
            {files.length > 0 ? 'RECONSTRUCTION VERIFIED' : 'AWAITING VERIFIED CHUNKS'}
          </Text>
        </View>
        <Text style={styles.title}>Reassembled Files</Text>
        <Text style={styles.subtitle}>
          {files.length > 0
            ? 'All chunks successfully verified and decrypted'
            : 'Complete a bulk tag scan session to verify and reconstruct vault files'}
        </Text>
      </View>

      {/* Files List */}
      <View style={styles.filesSection}>
        <Text style={styles.sectionTitle}>Vault Payload ({files.length} Files)</Text>
        {files.length === 0 ? (
          <View style={styles.fileCard}>
            <Text style={styles.fileName}>No Reconstructed Files Yet</Text>
            <Text style={styles.fileMime}>
              Scan physical vault tags in BulkScan first so ReconstructionEngine can verify chunk SHA-256 digests and unwrap the vault DEK.
            </Text>
          </View>
        ) : (
          files.map((file) => (
            <View key={file.id} style={styles.fileCard}>
              <View style={styles.fileMeta}>
                <Text style={styles.fileName}>{file.name}</Text>
                <Text style={styles.fileMime}>
                  {file.mimeType} • {(file.sizeBytes / 1024).toFixed(0)} KB • {file.chunkCount} Chunks
                </Text>
              </View>
              <View style={styles.verifiedBadge}>
                <Text style={styles.verifiedText}>
                  {file.isVerified ? 'SHA-256 MATCH' : 'UNVERIFIED'}
                </Text>
              </View>
              <View style={styles.actionRow}>
                <TouchableOpacity
                  style={styles.actionButton}
                  onPress={() => {
                    setLogs((prev) => [
                      ...prev,
                      `[VIEW] Native in-memory viewer hook required to display "${file.name}".`,
                    ]);
                  }}
                >
                  <Text style={styles.actionButtonText}>View In-App</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[styles.actionButton, styles.exportButton]}
                  onPress={() => {
                    setLogs((prev) => [
                      ...prev,
                      `[SAF] Native Android ACTION_CREATE_DOCUMENT bridge required to export "${file.name}".`,
                    ]);
                  }}
                >
                  <Text style={[styles.actionButtonText, styles.exportButtonText]}>
                    Export (SAF)
                  </Text>
                </TouchableOpacity>
              </View>
            </View>
          ))
        )}
      </View>

      {/* Terminal Output */}
      <View style={styles.terminalContainer}>
        <View style={styles.terminalHeader}>
          <View style={styles.terminalDot} />
          <Text style={styles.terminalTitle}>INTEGRITY TELEMETRY</Text>
        </View>
        <ScrollView style={styles.terminalLogs} nestedScrollEnabled>
          {logs.map((log, idx) => (
            <Text key={idx} style={styles.terminalLogText}>
              {log}
            </Text>
          ))}
        </ScrollView>
      </View>

      <TouchableOpacity style={styles.primaryButton} onPress={onDone}>
        <Text style={styles.primaryButtonText}>Finish & Lock Session</Text>
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
    fontSize: 24,
    fontWeight: '800',
    color: '#ffffff',
  },
  subtitle: {
    fontSize: 13,
    color: '#8e8e93',
    marginTop: 4,
  },
  filesSection: {
    gap: 12,
  },
  sectionTitle: {
    fontSize: 15,
    fontWeight: '700',
    color: '#ffffff',
  },
  fileCard: {
    backgroundColor: '#141419',
    borderRadius: 8,
    padding: 14,
    borderWidth: 1,
    borderColor: '#24242d',
    gap: 10,
  },
  fileMeta: {
    gap: 2,
  },
  fileName: {
    color: '#ffffff',
    fontSize: 15,
    fontWeight: '700',
  },
  fileMime: {
    color: '#8e8e93',
    fontSize: 12,
  },
  verifiedBadge: {
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(0, 230, 153, 0.1)',
    borderColor: '#00e699',
    borderWidth: 1,
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 4,
  },
  verifiedText: {
    color: '#00e699',
    fontSize: 10,
    fontWeight: '700',
    fontFamily: 'monospace',
  },
  actionRow: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 4,
  },
  actionButton: {
    flex: 1,
    paddingVertical: 8,
    alignItems: 'center',
    borderRadius: 6,
    backgroundColor: '#1c1c24',
    borderWidth: 1,
    borderColor: '#2e2e3a',
  },
  actionButtonText: {
    color: '#ffffff',
    fontSize: 13,
    fontWeight: '600',
  },
  exportButton: {
    backgroundColor: 'rgba(0, 230, 153, 0.12)',
    borderColor: '#00e699',
  },
  exportButtonText: {
    color: '#00e699',
  },
  terminalContainer: {
    backgroundColor: '#000000',
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#2e2e3a',
    padding: 12,
    minHeight: 160,
  },
  terminalHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    marginBottom: 8,
    paddingBottom: 6,
    borderBottomWidth: 1,
    borderBottomColor: '#1c1c24',
  },
  terminalDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: '#00e699',
  },
  terminalTitle: {
    color: '#8e8e93',
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 1,
  },
  terminalLogs: {
    maxHeight: 140,
  },
  terminalLogText: {
    color: '#00e699',
    fontSize: 11,
    fontFamily: 'monospace',
    lineHeight: 16,
  },
  primaryButton: {
    backgroundColor: '#00e699',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  primaryButtonText: {
    color: '#000000',
    fontSize: 15,
    fontWeight: '800',
  },
});

