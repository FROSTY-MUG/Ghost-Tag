/**
 * @file HomeScreen.tsx
 * @summary Ghost-Tag Primary Dashboard & Operational Navigation Hub.
 *
 * Provides instant access to Single-Tag Vault (v1), Bulk Distributed Vault (v2),
 * Passphrase & BIP39 Recovery, and Security Defense Settings.
 */

import React from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ScrollView,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { theme } from '@ghost-tag/ui/theme';
import type { RootStackParamList } from '../navigation/types';

export const HomeScreen: React.FC = () => {
  const navigation = useNavigation<NativeStackNavigationProp<RootStackParamList>>();

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.contentContainer}>
      {/* Brand Header */}
      <View style={styles.header}>
        <View style={styles.brandBadge}>
          <Text style={styles.brandBadgeText}>OFFLINE ENCRYPTED NFC VAULT</Text>
        </View>
        <Text style={styles.title}>GHOST-TAG</Text>
        <Text style={styles.subtitle}>
          Hardware-anchored distributed file & credential vault
        </Text>
      </View>

      {/* Core Promise & Limitation Banner */}
      <View style={styles.promiseBanner}>
        <Text style={styles.bannerTag}>CORE USER PROMISE</Text>
        <Text style={styles.bannerText}>
          "Ghost-Tag splits your encrypted files into pieces and stores one piece on each NFC tag. You can scan the tags in any order later. Ghost-Tag identifies each piece, verifies it, and reassembles your files when enough valid pieces are collected."
        </Text>
      </View>

      {/* Section 1: Single-Tag Vault (v1) */}
      <View style={styles.sectionCard}>
        <View style={styles.sectionHeader}>
          <Text style={styles.sectionTitle}>SINGLE-TAG VAULT (v1)</Text>
          <Text style={styles.sectionSub}>54-Byte Fixed Envelope • AES-256-GCM</Text>
        </View>

        <View style={styles.btnRow}>
          <TouchableOpacity
            style={styles.primaryActionBtn}
            onPress={() => navigation.navigate('ReadTag')}
            activeOpacity={0.8}
          >
            <Text style={styles.btnIcon}>📡</Text>
            <Text style={styles.primaryActionText}>READ / SCAN TAG</Text>
            <Text style={styles.btnSubtext}>Scan & decrypt single tag</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.secondaryActionBtn}
            onPress={() => navigation.navigate('WriteTag')}
            activeOpacity={0.8}
          >
            <Text style={styles.btnIcon}>💾</Text>
            <Text style={styles.secondaryActionText}>WRITE NEW TAG</Text>
            <Text style={styles.btnSubtext}>Encrypt & lock NTAG chip</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Section 2: Bulk Distributed Vault (v2) */}
      <View style={styles.sectionCard}>
        <View style={styles.sectionHeader}>
          <Text style={styles.sectionTitle}>BULK DISTRIBUTED VAULT (v2)</Text>
          <Text style={styles.sectionSub}>Cauchy Reed-Solomon GF(2^8) • Multi-Tag Sharding</Text>
        </View>

        <TouchableOpacity
          style={styles.fullWidthActionBtn}
          onPress={() => navigation.navigate('BulkVaultCreation')}
          activeOpacity={0.8}
        >
          <View style={styles.fullBtnContent}>
            <Text style={styles.btnIcon}>📁</Text>
            <View>
              <Text style={styles.fullBtnTitle}>CREATE DISTRIBUTED VAULT</Text>
              <Text style={styles.fullBtnSub}>Shard arbitrary files across physical tags</Text>
            </View>
          </View>
          <Text style={styles.chevron}>→</Text>
        </TouchableOpacity>

        <View style={[styles.btnRow, { marginTop: 10 }]}>
          <TouchableOpacity
            style={[styles.secondaryActionBtn, { flex: 1 }]}
            onPress={() => navigation.navigate('BulkScan', { totalRequiredChunks: 5 })}
            activeOpacity={0.8}
          >
            <Text style={styles.secondaryActionText}>SCAN TAGS (RANDOM)</Text>
            <Text style={styles.btnSubtext}>72h offline cache active</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.secondaryActionBtn, styles.flex1]}
            onPress={() => navigation.navigate('Reconstruction', { targetFileCount: 0 })}
            activeOpacity={0.8}
          >
            <Text style={styles.secondaryActionText}>RECONSTRUCT VAULT</Text>
            <Text style={styles.btnSubtext}>Solve Cauchy matrix</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Section 3: Passphrase & Security Settings */}
      <View style={styles.sectionCard}>
        <View style={styles.sectionHeader}>
          <Text style={styles.sectionTitle}>ROOT SECRETS & PLATFORM DEFENSE</Text>
          <Text style={styles.sectionSub}>Argon2id KDF • FLAG_SECURE • KeyStore TEE</Text>
        </View>

        <View style={styles.btnRow}>
          <TouchableOpacity
            style={[styles.secondaryActionBtn, styles.flex1]}
            onPress={() => navigation.navigate('Passphrase')}
            activeOpacity={0.8}
          >
            <Text style={styles.secondaryActionText}>PASSPHRASE & BIP39</Text>
            <Text style={styles.btnSubtext}>12-word recovery phrase</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.secondaryActionBtn, styles.flex1]}
            onPress={() => navigation.navigate('Settings')}
            activeOpacity={0.8}
          >
            <Text style={styles.secondaryActionText}>SECURITY SETTINGS</Text>
            <Text style={styles.btnSubtext}>Hardware defense matrix</Text>
          </TouchableOpacity>
        </View>
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
    marginTop: theme.spacing.md,
    marginBottom: theme.spacing.lg,
    alignItems: 'center',
  },
  brandBadge: {
    backgroundColor: 'rgba(0, 229, 255, 0.08)',
    borderColor: theme.colors.primary,
    borderWidth: 1,
    paddingHorizontal: 8,
    paddingVertical: 2,
    marginBottom: 6,
  },
  brandBadgeText: {
    color: theme.colors.primary,
    fontSize: 9,
    fontWeight: '800',
    letterSpacing: 1.5,
  },
  title: {
    fontSize: 32,
    fontWeight: '800',
    color: theme.colors.textPrimary,
    letterSpacing: 3,
  },
  subtitle: {
    fontSize: 12,
    color: theme.colors.textSecondary,
    marginTop: 4,
    textAlign: 'center',
  },
  promiseBanner: {
    backgroundColor: 'rgba(0, 255, 102, 0.03)',
    borderLeftWidth: 3,
    borderLeftColor: theme.colors.success,
    borderColor: theme.colors.border,
    borderWidth: 1,
    padding: 12,
    marginBottom: theme.spacing.lg,
  },
  bannerTag: {
    fontSize: 9,
    fontWeight: '800',
    color: theme.colors.success,
    letterSpacing: 1,
    marginBottom: 4,
  },
  bannerText: {
    fontSize: 11,
    color: theme.colors.textSecondary,
    lineHeight: 16,
    fontStyle: 'italic',
  },
  sectionCard: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderWidth: 1,
    padding: theme.spacing.md,
    marginBottom: theme.spacing.lg,
  },
  sectionHeader: {
    marginBottom: 12,
  },
  sectionTitle: {
    fontSize: 11,
    fontWeight: '800',
    color: theme.colors.primary,
    letterSpacing: 1,
  },
  sectionSub: {
    fontSize: 10,
    color: theme.colors.textMuted,
    marginTop: 2,
  },
  btnRow: {
    flexDirection: 'row',
    gap: 10,
  },
  primaryActionBtn: {
    flex: 1,
    backgroundColor: 'rgba(0, 229, 255, 0.1)',
    borderColor: theme.colors.primary,
    borderWidth: 1,
    padding: 12,
    alignItems: 'center',
  },
  primaryActionText: {
    color: theme.colors.primary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginTop: 4,
  },
  secondaryActionBtn: {
    flex: 1,
    backgroundColor: '#07090e',
    borderColor: theme.colors.border,
    borderWidth: 1,
    padding: 12,
    alignItems: 'center',
  },
  secondaryActionText: {
    color: theme.colors.textPrimary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginTop: 4,
  },
  btnIcon: {
    fontSize: 18,
  },
  btnSubtext: {
    fontSize: 9,
    color: theme.colors.textMuted,
    marginTop: 2,
    textAlign: 'center',
  },
  fullWidthActionBtn: {
    backgroundColor: 'rgba(178, 75, 243, 0.08)',
    borderColor: '#b24bf3',
    borderWidth: 1,
    padding: 12,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  fullBtnContent: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  fullBtnTitle: {
    color: '#ffffff',
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
  },
  fullBtnSub: {
    color: theme.colors.textMuted,
    fontSize: 10,
    marginTop: 2,
  },
  chevron: {
    color: '#b24bf3',
    fontSize: 16,
    fontWeight: '700',
  },
  flex1: {
    flex: 1,
  },
});
