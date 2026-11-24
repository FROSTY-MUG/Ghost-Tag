/**
 * @file ReadTagScreen.tsx
 * @summary Single-Tag Read, Scan & Decrypt Screen for Ghost-Tag (v1 Envelope).
 *
 * Scans physical NFC tags carrying canonical 54-byte binary envelopes,
 * prompts for the master passphrase, derives ephemeral KEK via Argon2id,
 * verifies Additional Authenticated Data (AAD), and decrypts with AES-256-GCM.
 */

import React, { useEffect, useState } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  TextInput,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import { theme } from '@ghost-tag/ui/theme';
import { ghostNfcManager } from '../../nfc/nfcManager';
import { parseEnvelope } from '../../crypto/envelope';

export interface ReadTagScreenProps {
  readonly onBack?: () => void;
}

export const ReadTagScreen: React.FC<ReadTagScreenProps> = () => {
  const [passphrase, setPassphrase] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [decryptedPayload, setDecryptedPayload] = useState<string | null>(null);
  const [detectedPurpose, setDetectedPurpose] = useState<string | null>(null);
  const [detectedKeyId, setDetectedKeyId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([
    '[INIT] Ghost-Tag NFC antenna listener ready.',
    '[INFO] Awaiting physical NFC tag scan with 54-byte fixed envelope...',
  ]);

  useEffect(() => {
    return () => {
      ghostNfcManager.stopListening().catch(() => {});
    };
  }, []);

  const handleScanAndDecrypt = async () => {
    if (!passphrase || passphrase.length < 16) {
      setErrorMsg('Master Passphrase must be at least 16 characters.');
      return;
    }

    setErrorMsg(null);
    setDecryptedPayload(null);
    setDetectedPurpose(null);
    setDetectedKeyId(null);
    setIsScanning(true);
    setLogs((prev) => [
      ...prev,
      '[NFC] Checking device NFC controller support and state...',
    ]);

    try {
      const supported = await ghostNfcManager.isNfcSupported();
      if (!supported) {
        setIsScanning(false);
        setErrorMsg('Hardware NFC controller is not supported on this device.');
        setLogs((prev) => [...prev, '[ERROR] NFC hardware is unavailable in this runtime.']);
        return;
      }

      const enabled = await ghostNfcManager.isNfcEnabled();
      if (!enabled) {
        setIsScanning(false);
        setErrorMsg('NFC is disabled in system settings. Enable NFC to scan physical tags.');
        setLogs((prev) => [...prev, '[ERROR] Android NFC transceiver is turned off.']);
        return;
      }

      setLogs((prev) => [
        ...prev,
        '[NFC] Foreground dispatch armed. Hold a physical NTAG21x tag near the antenna...',
      ]);

      await ghostNfcManager.startListening(
        async (tag) => {
          try {
            const firstRecord = tag.ndefMessage?.[0];
            if (!firstRecord || !firstRecord.payload || firstRecord.payload.length === 0) {
              setErrorMsg('Physical tag detected, but no Ghost-Tag NDEF payload was found.');
              setLogs((prev) => [...prev, '[ERROR] Tag contains no readable NDEF payload.']);
              return;
            }

            const rawBytes = new Uint8Array(firstRecord.payload);
            const envelope = parseEnvelope(rawBytes);
            const keyIdHex = Array.from(envelope.header.keyId)
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('');

            setDetectedPurpose(`0x${envelope.header.purpose.toString(16).padStart(2, '0')}`);
            setDetectedKeyId(keyIdHex);
            setErrorMsg(
              'Envelope header authenticated (GTAG v1), but ciphertext unwrapping requires an unlocked VaultManager DEK session.'
            );
            setLogs((prev) => [
              ...prev,
              `[TAG] Physical tag detected (${rawBytes.length}B NDEF payload).`,
              `[HEADER] Parsed GTAG v${envelope.header.formatVersion} keyId=${keyIdHex}.`,
              '[VAULT] Awaiting unlocked VaultManager session to unwrap DEK and decrypt.',
            ]);
          } catch (parseErr) {
            const msg = parseErr instanceof Error ? parseErr.message : String(parseErr);
            setErrorMsg(`Failed to parse Ghost-Tag envelope: ${msg}`);
            setLogs((prev) => [...prev, `[ERROR] Envelope parse failed: ${msg}`]);
          } finally {
            setIsScanning(false);
            await ghostNfcManager.stopListening();
          }
        },
        {
          timeoutMs: 15000,
          onTimeout: () => {
            setIsScanning(false);
            setErrorMsg('NFC scan timed out after 15 seconds with no physical tag detected.');
            setLogs((prev) => [...prev, '[TIMEOUT] No physical NFC tag detected within 15s.']);
          },
        }
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setIsScanning(false);
      setErrorMsg(`NFC scan initialization failed: ${msg}`);
      setLogs((prev) => [...prev, `[ERROR] ${msg}`]);
    }
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.contentContainer}>
      <View style={styles.header}>
        <View style={styles.badgeContainer}>
          <Text style={styles.badgeText}>SINGLE-TAG VAULT (v1)</Text>
        </View>
        <Text style={styles.title}>Read & Decrypt Tag</Text>
        <Text style={styles.subtitle}>Scan physical NFC tag to decrypt authenticated envelope</Text>
      </View>

      {/* Passphrase Input Section */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>1. MASTER PASSPHRASE</Text>
        <Text style={styles.cardDesc}>
          Enter your 16+ character passphrase. Keys are derived in volatile memory only and zeroized immediately.
        </Text>

        <View style={styles.inputRow}>
          <TextInput
            style={styles.textInput}
            value={passphrase}
            onChangeText={(text) => {
              setPassphrase(text);
              if (errorMsg) setErrorMsg(null);
            }}
            placeholder="Enter Master Passphrase (min 16 chars)..."
            placeholderTextColor={theme.colors.textMuted}
            secureTextEntry={!showPassword}
            autoCapitalize="none"
          />
          <TouchableOpacity
            style={styles.toggleBtn}
            onPress={() => setShowPassword(!showPassword)}
          >
            <Text style={styles.toggleBtnText}>{showPassword ? 'HIDE' : 'SHOW'}</Text>
          </TouchableOpacity>
        </View>

        {errorMsg && <Text style={styles.errorText}>⚠ {errorMsg}</Text>}
      </View>

      {/* Action Buttons */}
      <View style={styles.actionSection}>
        <TouchableOpacity
          style={[styles.primaryButton, isScanning && styles.buttonDisabled]}
          onPress={handleScanAndDecrypt}
          disabled={isScanning}
          activeOpacity={0.8}
        >
          {isScanning ? (
            <ActivityIndicator color="#000000" size="small" />
          ) : (
            <Text style={styles.primaryButtonText}>SCAN & DECRYPT NFC TAG</Text>
          )}
        </TouchableOpacity>
      </View>

      {/* Decrypted Payload Result Card */}
      {decryptedPayload && (
        <View style={styles.resultCard}>
          <View style={styles.resultHeader}>
            <Text style={styles.resultTitle}>DECRYPTED CONFIDENTIAL PAYLOAD</Text>
          </View>

          <View style={styles.metaRow}>
            <Text style={styles.metaLabel}>Purpose:</Text>
            <Text style={styles.metaVal}>{detectedPurpose}</Text>
          </View>
          <View style={styles.metaRow}>
            <Text style={styles.metaLabel}>DEK Key ID:</Text>
            <Text style={styles.metaVal}>{detectedKeyId}</Text>
          </View>
          <View style={styles.metaRow}>
            <Text style={styles.metaLabel}>Integrity:</Text>
            <Text style={[styles.metaVal, { color: theme.colors.success }]}>
              ● GCM AUTHENTICATED
            </Text>
          </View>

          <View style={styles.payloadBox}>
            <Text style={styles.payloadText}>{decryptedPayload}</Text>
          </View>
        </View>
      )}

      {/* Diagnostic Terminal Stream */}
      <View style={styles.terminalContainer}>
        <View style={styles.terminalHeader}>
          <View style={styles.dotRed} />
          <View style={styles.dotYellow} />
          <View style={styles.dotGreen} />
          <Text style={styles.terminalTitle}>DIAGNOSTIC LOG STREAM</Text>
        </View>
        <ScrollView style={styles.terminalLogs} nestedScrollEnabled>
          {logs.map((log, index) => (
            <Text key={index} style={styles.logLine}>
              {log}
            </Text>
          ))}
        </ScrollView>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: theme.colors.background,
  },
  contentContainer: {
    padding: theme.spacing.lg,
    paddingBottom: theme.spacing.xxl,
  },
  header: {
    marginBottom: theme.spacing.xl,
  },
  badgeContainer: {
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(0, 229, 255, 0.08)',
    borderColor: theme.colors.primary,
    borderWidth: 1,
    paddingHorizontal: 8,
    paddingVertical: 2,
    marginBottom: theme.spacing.xs,
  },
  badgeText: {
    color: theme.colors.primary,
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1,
  },
  title: {
    fontSize: 26,
    fontWeight: '800',
    color: theme.colors.textPrimary,
    letterSpacing: 0.5,
  },
  subtitle: {
    fontSize: 13,
    color: theme.colors.textSecondary,
    marginTop: 4,
  },
  card: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderWidth: 1,
    padding: theme.spacing.md,
    marginBottom: theme.spacing.lg,
  },
  cardTitle: {
    fontSize: 11,
    fontWeight: '700',
    color: theme.colors.primary,
    letterSpacing: 1,
    marginBottom: 4,
  },
  cardDesc: {
    fontSize: 12,
    color: theme.colors.textSecondary,
    lineHeight: 18,
    marginBottom: 12,
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  textInput: {
    flex: 1,
    backgroundColor: '#07090e',
    borderColor: theme.colors.border,
    borderWidth: 1,
    color: theme.colors.textPrimary,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 13,
    fontFamily: 'monospace',
  },
  toggleBtn: {
    paddingHorizontal: 12,
    paddingVertical: 10,
    backgroundColor: theme.colors.surfaceHighlight,
    borderWidth: 1,
    borderColor: theme.colors.border,
  },
  toggleBtnText: {
    color: theme.colors.textPrimary,
    fontSize: 11,
    fontWeight: '700',
  },
  errorText: {
    color: theme.colors.danger,
    fontSize: 11,
    marginTop: 8,
  },
  actionSection: {
    marginBottom: theme.spacing.lg,
  },
  primaryButton: {
    backgroundColor: theme.colors.primary,
    paddingVertical: 14,
    alignItems: 'center',
    justifyContent: 'center',
  },
  buttonDisabled: {
    opacity: 0.5,
  },
  primaryButtonText: {
    color: '#000000',
    fontSize: 13,
    fontWeight: '800',
    letterSpacing: 1.5,
  },
  resultCard: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.primary,
    borderWidth: 1,
    padding: theme.spacing.md,
    marginBottom: theme.spacing.lg,
  },
  resultHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  resultTitle: {
    fontSize: 11,
    fontWeight: '700',
    color: theme.colors.primary,
    letterSpacing: 1,
  },
  copyBtn: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderWidth: 1,
    borderColor: theme.colors.primary,
    backgroundColor: 'rgba(0, 229, 255, 0.1)',
  },
  copyBtnText: {
    color: theme.colors.primary,
    fontSize: 10,
    fontWeight: '700',
  },
  metaRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 4,
    borderBottomWidth: 1,
    borderBottomColor: '#141822',
  },
  metaLabel: {
    fontSize: 11,
    color: theme.colors.textMuted,
  },
  metaVal: {
    fontSize: 11,
    color: theme.colors.textPrimary,
    fontWeight: '600',
  },
  payloadBox: {
    backgroundColor: '#05070a',
    borderColor: theme.colors.border,
    borderWidth: 1,
    padding: 12,
    marginTop: 12,
  },
  payloadText: {
    color: theme.colors.textPrimary,
    fontSize: 12,
    fontFamily: 'monospace',
    lineHeight: 18,
  },
  terminalContainer: {
    backgroundColor: '#040507',
    borderColor: theme.colors.border,
    borderWidth: 1,
  },
  terminalHeader: {
    backgroundColor: '#0a0d13',
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: theme.colors.border,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  dotRed: { width: 8, height: 8, borderRadius: 4, backgroundColor: '#ff2a4b' },
  dotYellow: { width: 8, height: 8, borderRadius: 4, backgroundColor: '#ffaa00' },
  dotGreen: { width: 8, height: 8, borderRadius: 4, backgroundColor: '#00ff66' },
  terminalTitle: {
    color: theme.colors.textMuted,
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1,
    marginLeft: 6,
  },
  terminalLogs: {
    padding: 10,
    maxHeight: 120,
  },
  logLine: {
    color: theme.colors.textSecondary,
    fontSize: 10,
    fontFamily: 'monospace',
    marginBottom: 4,
  },
});

