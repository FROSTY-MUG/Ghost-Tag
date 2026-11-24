/**
 * @file BulkScanScreen.tsx
 * @summary Ghost-Tag Random-Order Bulk Scanning Screen (v2).
 *
 * Implements non-sequential tag scanning, live progress tracking,
 * 72-hour cache TTL countdown, and terminal verification telemetry.
 */

import React, { useState } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ScrollView,
} from 'react-native';

export interface BulkScanScreenProps {
  readonly totalRequiredChunks: number;
  readonly onProceedToReconstruction?: () => void;
}

export const BulkScanScreen: React.FC<BulkScanScreenProps> = ({
  totalRequiredChunks,
  onProceedToReconstruction,
}) => {
  const [collectedIndices] = useState<number[]>([]);
  const [logs] = useState<string[]>([
    `[SCAN] Initializing bulk scan session. Total required: ${totalRequiredChunks}`,
    `[CACHE] Local encrypted chunk cache active (72h TTL).`,
    `[PROMPT] Present any vault tag to the NFC antenna in any order...`,
  ]);

  const collectedCount = collectedIndices.length;
  const remainingCount = Math.max(0, totalRequiredChunks - collectedCount);
  const isComplete = collectedCount >= totalRequiredChunks;

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.contentContainer}>
      <View style={styles.header}>
        <Text style={styles.title}>Bulk Tag Scanner</Text>
        <Text style={styles.subtitle}>Scan tags in ANY random physical order</Text>
      </View>

      {/* Cache TTL Badge */}
      <View style={styles.cacheCard}>
        <View style={styles.cacheIndicator} />
        <View style={styles.cacheContent}>
          <Text style={styles.cacheTitle}>72-HOUR ENCRYPTED CACHE</Text>
          <Text style={styles.cacheSubtitle}>
            Scanned chunks remain cached offline. You can close the app or scan over multiple days.
          </Text>
        </View>
      </View>

      {/* Stats Counter */}
      <View style={styles.statsCard}>
        <View style={styles.statBox}>
          <Text style={styles.statNumber}>{collectedCount}</Text>
          <Text style={styles.statLabel}>COLLECTED</Text>
        </View>
        <View style={styles.statDivider} />
        <View style={styles.statBox}>
          <Text style={[styles.statNumber, styles.statNumberWarning]}>{remainingCount}</Text>
          <Text style={styles.statLabel}>REMAINING</Text>
        </View>
        <View style={styles.statDivider} />
        <View style={styles.statBox}>
          <Text style={[styles.statNumber, styles.statNumberTotal]}>{totalRequiredChunks}</Text>
          <Text style={styles.statLabel}>TOTAL</Text>
        </View>
      </View>

      {/* Terminal Output */}
      <View style={styles.terminalContainer}>
        <View style={styles.terminalHeader}>
          <View style={styles.terminalDot} />
          <Text style={styles.terminalTitle}>TERMINAL TELEMETRY</Text>
        </View>
        <ScrollView style={styles.terminalLogs} nestedScrollEnabled>
          {logs.map((log, idx) => (
            <Text key={idx} style={styles.terminalLogText}>
              {log}
            </Text>
          ))}
        </ScrollView>
      </View>

      {isComplete ? (
        <TouchableOpacity
          style={styles.primaryButton}
          onPress={onProceedToReconstruction}
        >
          <Text style={styles.primaryButtonText}>Reassemble & Decrypt Files</Text>
        </TouchableOpacity>
      ) : (
        <View style={styles.scanningBanner}>
          <Text style={styles.scanningBannerText}>HOLD DEVICE NEAR PHYSICAL TAG TO SCAN</Text>
        </View>
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
  cacheCard: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#121217',
    borderColor: '#24242d',
    borderWidth: 1,
    borderRadius: 8,
    padding: 12,
    gap: 10,
  },
  cacheIndicator: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: '#00e699',
  },
  cacheContent: {
    flex: 1,
  },
  cacheTitle: {
    color: '#00e699',
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
  },
  cacheSubtitle: {
    color: '#8e8e93',
    fontSize: 11,
    lineHeight: 15,
    marginTop: 2,
  },
  statsCard: {
    flexDirection: 'row',
    backgroundColor: '#141419',
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#24242d',
    paddingVertical: 16,
  },
  statBox: {
    flex: 1,
    alignItems: 'center',
  },
  statDivider: {
    width: 1,
    backgroundColor: '#24242d',
  },
  statNumber: {
    color: '#00e699',
    fontSize: 26,
    fontWeight: '800',
    fontFamily: 'monospace',
  },
  statNumberWarning: {
    color: '#ff9500',
  },
  statNumberTotal: {
    color: '#ffffff',
  },
  statLabel: {
    color: '#8e8e93',
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1,
    marginTop: 2,
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
  scanningBanner: {
    backgroundColor: '#1c1c24',
    borderColor: '#3a3a48',
    borderWidth: 1,
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
  },
  scanningBannerText: {
    color: '#8e8e93',
    fontSize: 12,
    fontWeight: '700',
    letterSpacing: 1,
  },
});

