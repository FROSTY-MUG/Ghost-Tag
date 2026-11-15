/**
 * @file DeleteEntryModal.tsx
 * @summary Ghost-Tag v2.0.5 Android Entry Deletion Corruption Warning Modal.
 *
 * Requirements:
 * - Mandatory explicit corruption warning dialog before starting any entry deletion
 * - Exact warning text according to Section 13 of Ghost-Tag System Manual:
 *   "DELETE ENTRY"
 *   "Entry: <entryName>"
 *   "Deleting this entry requires rewriting encrypted Ghost data on the affected NFC tags."
 *   "This operation may fail if a tag is damaged, removed too early, or becomes unreadable."
 *   "Existing entries may become temporarily unavailable until the rewrite completes."
 *   [CANCEL]  [DELETE ENTRY]
 */

import React from 'react';
import {
  Modal,
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  AccessibilityRole,
} from 'react-native';
import { theme } from '../theme';
import {
  DELETE_ENTRY_WARNING_HEADER,
  DELETE_ENTRY_WARNING_BODY,
} from '../../operations/deleteEntryOperation';

export interface DeleteEntryModalProps {
  visible: boolean;
  entryName: string;
  isRewriting?: boolean;
  onCancel: () => void;
  onConfirmDelete: () => void;
}

export const DeleteEntryModal: React.FC<DeleteEntryModalProps> = ({
  visible,
  entryName,
  isRewriting = false,
  onCancel,
  onConfirmDelete,
}) => {
  return (
    <Modal
      transparent
      animationType="fade"
      visible={visible}
      onRequestClose={onCancel}
    >
      <View style={styles.backdrop}>
        <View style={styles.dialog}>
          {/* Header */}
          <Text style={styles.title}>{DELETE_ENTRY_WARNING_HEADER}</Text>

          {/* Target Entry */}
          <View style={styles.entryBox}>
            <Text style={styles.entryLabel}>Entry:</Text>
            <Text style={styles.entryName}>{entryName}</Text>
          </View>

          {/* Warning Message */}
          <View style={styles.warningBox}>
            <Text style={styles.warningText}>{DELETE_ENTRY_BODY}</Text>
          </View>

          {/* Action Buttons */}
          <View style={styles.buttonRow}>
            <TouchableOpacity
              style={[styles.button, styles.cancelButton]}
              onPress={onCancel}
              disabled={isRewriting}
              accessibilityRole={'button' as AccessibilityRole}
              accessibilityLabel="Cancel Deletion"
            >
              <Text style={styles.cancelButtonText}>CANCEL</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={[styles.button, styles.deleteButton, isRewriting && styles.buttonDisabled]}
              onPress={onConfirmDelete}
              disabled={isRewriting}
              accessibilityRole={'button' as AccessibilityRole}
              accessibilityLabel="Confirm Delete Entry"
            >
              <Text style={styles.deleteButtonText}>
                {isRewriting ? 'REWRITING...' : 'DELETE ENTRY'}
              </Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
};

const DELETE_ENTRY_BODY = DELETE_ENTRY_WARNING_BODY;

const styles = StyleSheet.create({
  backdrop: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.85)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: theme.spacing.lg,
  },
  dialog: {
    width: '100%',
    maxWidth: 440,
    backgroundColor: '#0A0A0A',
    borderWidth: 1,
    borderColor: '#333333',
    borderRadius: theme.borderRadius.sm,
    padding: theme.spacing.xl,
  },
  title: {
    fontFamily: 'monospace',
    fontSize: 20,
    fontWeight: 'bold',
    color: '#FF4444',
    letterSpacing: 2,
    marginBottom: theme.spacing.md,
    textAlign: 'center',
  },
  entryBox: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#141414',
    borderWidth: 1,
    borderColor: '#222222',
    padding: theme.spacing.md,
    marginBottom: theme.spacing.md,
  },
  entryLabel: {
    fontFamily: 'monospace',
    fontSize: 14,
    color: '#888888',
    marginRight: theme.spacing.sm,
  },
  entryName: {
    fontFamily: 'monospace',
    fontSize: 14,
    color: '#FFFFFF',
    fontWeight: '600',
    flexShrink: 1,
  },
  warningBox: {
    backgroundColor: '#180B0B',
    borderLeftWidth: 3,
    borderLeftColor: '#FF4444',
    padding: theme.spacing.md,
    marginBottom: theme.spacing.xl,
  },
  warningText: {
    fontFamily: 'system-ui',
    fontSize: 13,
    lineHeight: 20,
    color: '#E0E0E0',
  },
  buttonRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: theme.spacing.md,
  },
  button: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: theme.borderRadius.sm,
    alignItems: 'center',
    justifyContent: 'center',
  },
  cancelButton: {
    backgroundColor: '#1E1E1E',
    borderWidth: 1,
    borderColor: '#333333',
  },
  cancelButtonText: {
    fontFamily: 'monospace',
    fontSize: 13,
    fontWeight: '600',
    color: '#CCCCCC',
    letterSpacing: 1,
  },
  deleteButton: {
    backgroundColor: '#D32F2F',
  },
  deleteButtonText: {
    fontFamily: 'monospace',
    fontSize: 13,
    fontWeight: 'bold',
    color: '#FFFFFF',
    letterSpacing: 1,
  },
  buttonDisabled: {
    opacity: 0.5,
  },
});
