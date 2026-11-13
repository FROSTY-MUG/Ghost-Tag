/**
 * @file BulkWriteScreen.tsx
 * @summary Ghost-Tag Bulk Sequential Tag Writing Screen (v2).
 *
 * Implements interactive bulk-writing with strict extra-tag exclusion,
 * write-and-verify progress tracking, and terminal diagnostics.
 */

import React, { useState } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ScrollView,
} from 'react-native';

export interface BulkWriteScreenProps {
  readonly requiredTagCount: number;
  readonly presentedTagCount: number;
  readonly onFinish?: () => void;
}

export const BulkWriteScreen: React.FC<BulkWriteScreenProps> = ({
  requiredTagCount,
  presentedTagCount,
  onFinish,
}) => {
  const extraTags = Math.max(0, presentedTagCount - requiredTagCount);
  const [currentChunk, setCurrentChunk] = useState<number>(1);
  const [logs, setLogs] = useState<string[]>([
    `[PLAN] Target chunks required: ${requiredTagCount}`,
    extraTags > 0
      ? `[EXCLUDE] Only ${requiredTagCount} tags are required. Please set aside the other ${extraTags} tags. Scan the ${requiredTagCount} required tags one by one.`
      : `[PLAN] Scan ${requiredTagCount} tags one by one.`,
    `[WAIT] Present tag for Chunk #${currentChunk}...`,
  ]);

  const progressPct = Math.min(100, Math.round(((currentChunk - 1) / requiredTagCount) * 100));

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.contentContainer}>
      <View style={styles.header}>
        <Text style={styles.title}>Bulk Tag Writer</Text>
        <Text style={styles.subtitle}>Sequential Fragment Distribution</Text>
      </View>

      {/* Extra Tag Warning Banner */}
      {extraTags > 0 && (
        <View style={styles.warningCard}>
          <Text style={styles.warningTitle}>EXTRA TAGS EXCLUDED</Text>
          <Text style={styles.warningText}>
            Only {requiredTagCount} tags are required. Please set aside the other {extraTags} tags.
            Scan the {requiredTagCount} required tags one by one.
          </Text>
        </View>
      )}

      {/* Progress Card */}
      <View style={styles.progressCard}>
        <View style={styles.progressHeader}>
          <Text style={styles.progressLabel}>Write Progress</Text>
          <Text style={styles.progressCount}>
            {currentChunk - 1} / {requiredTagCount} ({progressPct}%)
          </Text>
        </View>
        <View style={styles.progressBarBg}>
          <View style={[styles.progressBarFill, { width: `${progressPct}%` }]} />
        </View>
        <Text style={styles.statusText}>
          {currentChunk <= requiredTagCount
            ? `Ready for Tag #${currentChunk}. Tap tag to NFC antenna.`
            : 'All required tags written and verified successfully!'}
        </Text>
      </View>

      {/* Terminal Output */}
      <View style={styles.terminalContainer}>
        <View style={styles.terminalHeader}>
          <View style={styles.terminalDot} />
          <Text style={styles.terminalTitle}>TERMINAL DIAGNOSTICS</Text>
        </View>
        <ScrollView style={styles.terminalLogs} nestedScrollEnabled>
          {logs.map((log, idx) => (
            <Text key={idx} style={styles.terminalLogText}>
              {log}
            </Text>
          ))}
        </ScrollView>
      </View>

      {currentChunk > requiredTagCount ? (
        <TouchableOpacity style={styles.primaryButton} onPress={onFinish}>
          <Text style={styles.primaryButtonText}>Complete & Seal Vault</Text>
        </TouchableOpacity>
      ) : (
        <TouchableOpacity
          style={styles.simulateButton}
          onPress={() => {
            const next = currentChunk + 1;
            setCurrentChunk(next);
            setLogs((prev) => [
              ...prev,
              `[WRITE] Chunk #${currentChunk} written to tag.`,
              `[VERIFY] Read-back hash verified. AES-256-GCM auth tag verified.`,
              next <= requiredTagCount
                ? `[WAIT] Present tag for Chunk #${next}...`
                : `[RESULT] All ${requiredTagCount} tags successfully written and verified!`,
            ]);
          }}
        >
          <Text style={styles.simulateButtonText}>Simulate Tag Write & Verify</Text>
        </TouchableOpacity>
      )}
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
  warningCard: {
    backgroundColor: '#1f1609',
    borderColor: '#ff9500',
    borderWidth: 1,
    borderRadius: 8,
    padding: 14,
  },
  warningTitle: {
    color: '#ff9500',
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 4,
  },
  warningText: {
    color: '#ffdca8',
    fontSize: 13,
    lineHeight: 18,
  },
  progressCard: {
    backgroundColor: '#141419',
    borderRadius: 8,
    padding: 16,
    borderWidth: 1,
    borderColor: '#24242d',
  },
  progressHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  progressLabel: {
    color: '#ffffff',
    fontSize: 14,
    fontWeight: '600',
  },
  progressCount: {
    color: '#00e699',
    fontSize: 14,
    fontWeight: '700',
    fontFamily: 'monospace',
  },
  progressBarBg: {
    height: 8,
    backgroundColor: '#24242d',
    borderRadius: 4,
    overflow: 'hidden',
    marginBottom: 10,
  },
  progressBarFill: {
    height: '100%',
    backgroundColor: '#00e699',
  },
  statusText: {
    color: '#8e8e93',
    fontSize: 12,
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
  simulateButton: {
    backgroundColor: '#1c1c24',
    borderColor: '#3a3a48',
    borderWidth: 1,
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  simulateButtonText: {
    color: '#ffffff',
    fontSize: 14,
    fontWeight: '600',
  },
});
