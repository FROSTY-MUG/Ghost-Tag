/**
 * @file vault.test.ts
 * @summary Unit and Integration Tests for Ghost-Tag Phase 3 Vault Subsystem.
 */

import { Buffer } from 'buffer';
import {
  VaultDatabase,
  VaultManager,
  VaultSession,
  DEKManager,
  RecoveryManager,
  VaultManifest,
  AuditLog,
  BIP39_ENGLISH_WORDLIST,
  getWord,
  getWordIndex,
  isValidWord,
} from '../vault';
import {
  KeyStatus,
  AuditEventType,
  GhostTagError,
} from '../contracts';
import { zeroize } from '../crypto/secureMemory';

describe('Phase 3 Vault Subsystem', () => {
  // -------------------------------------------------------------------------
  // 1. BIP39 Wordlist
  // -------------------------------------------------------------------------
  describe('BIP39 Wordlist', () => {
    it('contains exactly 2048 words with proper boundaries', () => {
      expect(BIP39_ENGLISH_WORDLIST.length).toBe(2048);
      expect(getWord(0)).toBe('abandon');
      expect(getWord(2047)).toBe('zoo');
      expect(getWordIndex('abandon')).toBe(0);
      expect(getWordIndex('zoo')).toBe(2047);
      expect(isValidWord('abandon')).toBe(true);
      expect(isValidWord('zoo')).toBe(true);
      expect(isValidWord('notawordxyz')).toBe(false);
      expect(() => getWord(-1)).toThrow(RangeError);
      expect(() => getWord(2048)).toThrow(RangeError);
    });
  });

  // -------------------------------------------------------------------------
  // 2. VaultDatabase
  // -------------------------------------------------------------------------
  describe('VaultDatabase', () => {
    let db: VaultDatabase;
    const testKey = new Uint8Array(32).fill(0x42);

    beforeEach(async () => {
      db = new VaultDatabase('test_db_' + Date.now());
      await db.initialize(testKey);
    });

    afterEach(async () => {
      await db.close();
    });

    it('stores, retrieves, checks existence, and deletes byte arrays', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      await db.store('key1', data);

      expect(await db.exists('key1')).toBe(true);
      expect(await db.exists('key2')).toBe(false);

      const retrieved = await db.retrieve('key1');
      expect(retrieved).not.toBeNull();
      expect(retrieved).toEqual(data);

      expect(await db.retrieve('key2')).toBeNull();

      await db.delete('key1');
      expect(await db.exists('key1')).toBe(false);
      expect(await db.retrieve('key1')).toBeNull();
    });

    it('throws error if accessing store before initialization', async () => {
      const uninitDb = new VaultDatabase('uninit_db');
      await expect(uninitDb.store('k', new Uint8Array([1]))).rejects.toThrow(GhostTagError);
    });
  });

  // -------------------------------------------------------------------------
  // 3. VaultSession
  // -------------------------------------------------------------------------
  describe('VaultSession', () => {
    it('manages volatile KEK lifecycle, lock, and auto-lock', () => {
      const kek = new Uint8Array(32).fill(0xaa);
      const session = new VaultSession(kek, undefined, 1000);

      expect(session.isUnlocked).toBe(true);
      expect(session.sessionId).toHaveLength(32);

      const retrievedKek = session.getKEK();
      expect(retrievedKek).toEqual(kek);

      session.lock();
      expect(session.isUnlocked).toBe(false);
      expect(session.getKEK()).toBeNull();
    });

    it('triggers lock upon application backgrounding', () => {
      const kek = new Uint8Array(32).fill(0xbb);
      const session = new VaultSession(kek);

      expect(session.isUnlocked).toBe(true);
      session.handleAppStateChange('background');
      expect(session.isUnlocked).toBe(false);
      expect(session.getKEK()).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // 4. DEKManager
  // -------------------------------------------------------------------------
  describe('DEKManager', () => {
    let db: VaultDatabase;
    let dekManager: DEKManager;
    const kek = new Uint8Array(32).fill(0x33);

    beforeEach(async () => {
      db = new VaultDatabase('test_dek_db_' + Date.now());
      await db.initialize(new Uint8Array(32).fill(1));
      dekManager = new DEKManager(db);
    });

    afterEach(async () => {
      await db.close();
    });

    it('creates, unwraps, rotates, and revokes DEKs', async () => {
      // 1. Create DEK
      const wrapped = await dekManager.createDEK(kek);
      expect(wrapped.keyId).toHaveLength(32);
      expect(wrapped.status).toBe(KeyStatus.ACTIVE);
      expect(wrapped.keyVersion).toBe(1);

      const keyIdBytes = new Uint8Array(16);
      for (let i = 0; i < 16; i++) {
        keyIdBytes[i] = parseInt(wrapped.keyId.substring(i * 2, i * 2 + 2), 16);
      }

      // 2. Unwrap DEK
      const rawDek = await dekManager.getDEK(keyIdBytes, kek);
      expect(rawDek).toHaveLength(32);
      zeroize(rawDek);

      // 3. List Key IDs
      const keyIds = await dekManager.listKeyIds();
      expect(keyIds.length).toBe(1);
      expect(keyIds[0]).toEqual(keyIdBytes);

      // 4. Rotate DEK
      const rotatedNew = await dekManager.rotateDEK(keyIdBytes, kek);
      expect(await dekManager.getKeyStatus(keyIdBytes)).toBe(KeyStatus.ROTATED);
      expect(rotatedNew.status).toBe(KeyStatus.ACTIVE);
      expect(rotatedNew.keyId).not.toBe(wrapped.keyId);

      // 5. Revoke DEK
      await dekManager.revokeDEK(keyIdBytes);
      expect(await dekManager.getKeyStatus(keyIdBytes)).toBe(KeyStatus.REVOKED);
      await expect(dekManager.getDEK(keyIdBytes, kek)).rejects.toThrow(GhostTagError);
    });
  });

  // -------------------------------------------------------------------------
  // 5. RecoveryManager
  // -------------------------------------------------------------------------
  describe('RecoveryManager', () => {
    let db: VaultDatabase;
    let dekManager: DEKManager;
    let recoveryManager: RecoveryManager;
    const kek = new Uint8Array(32).fill(0x55);

    beforeEach(async () => {
      db = new VaultDatabase('test_rec_db_' + Date.now());
      await db.initialize(new Uint8Array(32).fill(2));
      dekManager = new DEKManager(db);
      recoveryManager = new RecoveryManager(db);
    });

    afterEach(async () => {
      await db.close();
    });

    it('generates, verifies, sets up, and recovers vault DEKs', async () => {
      // Generate phrase
      const { phrase, words } = recoveryManager.generateRecoveryPhrase();
      expect(words).toHaveLength(24);
      expect(await recoveryManager.verifyRecoveryPhrase(phrase)).toBe(true);

      // Invalid phrase checks
      expect(await recoveryManager.verifyRecoveryPhrase('invalid words')).toBe(false);
      const invalidDictWords = [...words];
      invalidDictWords[0] = 'notawordxyz';
      expect(await recoveryManager.verifyRecoveryPhrase(invalidDictWords.join(' '))).toBe(false);

      const corruptedWords = [...words];
      corruptedWords[corruptedWords.length - 1] =
        corruptedWords[corruptedWords.length - 1] === 'abandon' ? 'ability' : 'abandon';
      let corruptedResult = await recoveryManager.verifyRecoveryPhrase(corruptedWords.join(' '));
      if (corruptedResult) {
        // Handle rare 1/256 random checksum collision on single word replacement
        corruptedWords[corruptedWords.length - 1] =
          corruptedWords[corruptedWords.length - 1] === 'zoo' ? 'zone' : 'zoo';
        corruptedResult = await recoveryManager.verifyRecoveryPhrase(corruptedWords.join(' '));
      }
      expect(corruptedResult).toBe(false);

      // Create a DEK to protect
      const dek1 = await dekManager.createDEK(kek);
      const rawDek1 = await dekManager.getDEK(
        new Uint8Array(Buffer.from(dek1.keyId, 'hex')),
        kek
      );

      // Setup recovery
      await recoveryManager.setupRecovery(phrase, kek, [dek1]);
      expect(await recoveryManager.isRecoveryConfigured()).toBe(true);

      // Recover vault
      const result = await recoveryManager.recoverVault(phrase);
      expect(result.success).toBe(true);
      expect(result.recoveredDekCount).toBe(1);
      expect(result.recoveredDeks[0].keyId).toBe(dek1.keyId);
      expect(result.recoveredDeks[0].dek).toEqual(rawDek1);

      zeroize(rawDek1);
      zeroize(result.recoveredDeks[0].dek);
    });

    it('supports standard 12-word BIP-39 recovery phrases and confirmation indices', async () => {
      const { phrase, words } = recoveryManager.generate12WordPhrase();
      expect(words).toHaveLength(12);
      expect(await recoveryManager.verifyRecoveryPhrase(phrase)).toBe(true);

      // Verify words 4, 8, 11 confirmation check
      expect(
        recoveryManager.verifyConfirmationWords(
          words,
          words[3],
          words[7],
          words[10]
        )
      ).toBe(true);

      expect(
        recoveryManager.verifyConfirmationWords(
          words,
          words[3] + '_mismatch',
          words[7],
          words[10]
        )
      ).toBe(false);

      // Test corrupt checksum
      const badWords = [...words];
      const lastWordIdx = getWordIndex(badWords[11]);
      badWords[11] = getWord(lastWordIdx ^ 1);
      expect(await recoveryManager.verifyRecoveryPhrase(badWords.join(' '))).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // 6. VaultManifest
  // -------------------------------------------------------------------------
  describe('VaultManifest', () => {
    const manifest = new VaultManifest();
    const salt = new Uint8Array(16).fill(0x12);
    const kdfParams = {
      salt,
      memoryCost: 32768,
      timeCost: 3,
      parallelism: 2,
      version: 0x13,
    };

    it('computes and verifies manifest authentication tag', () => {
      const vaultData = {
        vaultId: '1234567890abcdef1234567890abcdef',
        creationTime: Date.now(),
        argon2Salt: salt,
        argon2Params: kdfParams,
        wrappedDEKs: [],
      };

      const tag = manifest.computeManifestTag(vaultData);
      expect(tag).toHaveLength(16);
      expect(manifest.verifyManifest(vaultData, tag)).toBe(true);

      // Altered tag fails
      const badTag = new Uint8Array(tag);
      badTag[0] ^= 0xff;
      expect(manifest.verifyManifest(vaultData, badTag)).toBe(false);
    });

    it('detects tampering and parameter downgrades', () => {
      const goodVault = {
        vaultId: '1234567890abcdef1234567890abcdef',
        creationTime: Date.now(),
        argon2Salt: salt,
        argon2Params: kdfParams,
        wrappedDEKs: [],
      };

      expect(manifest.detectTampering(goodVault).isTampered).toBe(false);

      // Downgraded memoryCost
      const downgraded = {
        ...goodVault,
        argon2Params: { ...kdfParams, memoryCost: 8192 },
      };
      const tamperResult = manifest.detectTampering(downgraded);
      expect(tamperResult.isTampered).toBe(true);
      expect(tamperResult.reason).toContain('downgraded');
    });
  });

  // -------------------------------------------------------------------------
  // 7. AuditLog
  // -------------------------------------------------------------------------
  describe('AuditLog', () => {
    let db: VaultDatabase;
    let auditLog: AuditLog;

    beforeEach(async () => {
      db = new VaultDatabase('test_audit_db_' + Date.now());
      await db.initialize(new Uint8Array(32).fill(3));
      auditLog = new AuditLog(db);
    });

    afterEach(async () => {
      await db.close();
    });

    it('logs allowed events and computes rolling hash chain', async () => {
      await auditLog.logEvent({
        eventId: 'event-1',
        eventType: AuditEventType.VAULT_CREATED,
        timestamp: 1000,
        resultCode: 0,
        tagFamily: null,
        keyId: null,
        envelopeVersion: null,
        errorCode: null,
      });

      const hash1 = await auditLog.getAuditHash();
      expect(hash1).toHaveLength(32);

      await auditLog.logEvent({
        eventId: 'event-2',
        eventType: AuditEventType.DEK_GENERATED,
        timestamp: 2000,
        resultCode: 0,
        tagFamily: null,
        keyId: '0123456789abcdef0123456789abcdef',
        envelopeVersion: 1,
        errorCode: null,
      });

      const hash2 = await auditLog.getAuditHash();
      expect(hash2).not.toEqual(hash1);

      const events = await auditLog.getEvents();
      expect(events).toHaveLength(2);

      const filtered = await auditLog.getEvents({ eventType: AuditEventType.DEK_GENERATED });
      expect(filtered).toHaveLength(1);
      expect(filtered[0].eventId).toBe('event-2');
    });

    it('strictly rejects forbidden sensitive fields', async () => {
      const forbiddenPayload: any = {
        eventId: 'event-bad',
        eventType: AuditEventType.VAULT_UNLOCKED,
        timestamp: Date.now(),
        resultCode: 0,
        passphrase: 'supersecretpassword', // Forbidden!
      };

      await expect(auditLog.logEvent(forbiddenPayload)).rejects.toThrow(GhostTagError);
    });
  });

  // -------------------------------------------------------------------------
  // 8. VaultManager (End-to-End Vault Lifecycle)
  // -------------------------------------------------------------------------
  describe('VaultManager', () => {
    let db: VaultDatabase;
    let vaultManager: VaultManager;

    beforeEach(async () => {
      db = new VaultDatabase('test_mgr_db_' + Date.now());
      await db.initialize(new Uint8Array(32).fill(4));
      vaultManager = new VaultManager(db);
    });

    afterEach(async () => {
      await vaultManager.deleteVault();
      await db.close();
    });

    it('creates, opens, introspects, locks, and deletes vault', async () => {
      expect(await vaultManager.isVaultInitialized()).toBe(false);

      // Create Vault
      const createResult = await vaultManager.createVault('master-test-passphrase-123');
      expect(createResult.vaultId).toBeDefined();
      expect(createResult.session.isUnlocked).toBe(true);
      expect(createResult.initialDekId).toHaveLength(32);
      expect(await vaultManager.isVaultInitialized()).toBe(true);

      // Cannot recreate
      await expect(vaultManager.createVault('another-pass')).rejects.toThrow(GhostTagError);

      // Read metadata without passphrase
      const metadata = await vaultManager.getVaultMetadata();
      expect(metadata.vaultId).toBe(createResult.vaultId);
      expect(metadata.wrappedDekCount).toBe(1);
      expect(metadata.keyIds).toContain(createResult.initialDekId);

      // Lock Vault
      vaultManager.lockVault();
      expect(vaultManager.getSession()).toBeNull();

      // Open with wrong passphrase fails
      await expect(vaultManager.openVault('wrong-passphrase')).rejects.toThrow(GhostTagError);

      // Open with correct passphrase succeeds
      const session = await vaultManager.openVault('master-test-passphrase-123');
      expect(session.isUnlocked).toBe(true);
      expect(session.getKEK()).toHaveLength(32);

      // Delete Vault
      await vaultManager.deleteVault();
      expect(await vaultManager.isVaultInitialized()).toBe(false);
    });
  });
});

