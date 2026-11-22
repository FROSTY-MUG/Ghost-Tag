import Foundation
import CryptoKit

public enum RecoveryDerivationError: Error, LocalizedError {
    case invalidWordCount(Int)
    case derivationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidWordCount(let count):
            return "Recovery phrase must contain exactly 12 words (received \(count))."
        case .derivationFailed(let msg):
            return "Recovery derivation failed: \(msg)"
        }
    }
}

public enum RecoveryDerivation {
    public static let accountIdPrefix = "ghost-account-id-v2.0.5:"
    public static let recoveryAuthPrefix = "ghost-recovery-auth-v2.0.5:"

    /// Derives canonical RFC 4122 v4 UUID account_id from 12-word BIP-39 recovery phrase
    public static func deriveAccountId(phrase: String) throws -> UUID {
        let words = BIP39.normalize(phrase: phrase)
        guard words.count == 12 else {
            throw RecoveryDerivationError.invalidWordCount(words.count)
        }
        let cleanPhrase = words.joined(separator: " ")
        guard let data = (accountIdPrefix + cleanPhrase).data(using: .utf8) else {
            throw RecoveryDerivationError.derivationFailed("Failed to encode UTF-8 input")
        }

        var hashBytes = Array(SHA256.hash(data: data)) // 32 bytes
        // RFC 4122 v4 UUID formatting:
        // byte 6: version 4 (0100xxxx) -> (b & 0x0f) | 0x40
        // byte 8: variant 1 (10xxxxxx) -> (b & 0x3f) | 0x80
        hashBytes[6] = (hashBytes[6] & 0x0f) | 0x40
        hashBytes[8] = (hashBytes[8] & 0x3f) | 0x80

        let uuidBytes: uuid_t = (
            hashBytes[0], hashBytes[1], hashBytes[2], hashBytes[3],
            hashBytes[4], hashBytes[5], hashBytes[6], hashBytes[7],
            hashBytes[8], hashBytes[9], hashBytes[10], hashBytes[11],
            hashBytes[12], hashBytes[13], hashBytes[14], hashBytes[15]
        )
        return UUID(uuid: uuidBytes)
    }

    /// Derives 32-byte recovery_auth_secret from 12-word BIP-39 recovery phrase
    public static func deriveRecoveryAuthSecret(phrase: String) throws -> Data {
        let words = BIP39.normalize(phrase: phrase)
        guard words.count == 12 else {
            throw RecoveryDerivationError.invalidWordCount(words.count)
        }
        let cleanPhrase = words.joined(separator: " ")
        guard let data = (recoveryAuthPrefix + cleanPhrase).data(using: .utf8) else {
            throw RecoveryDerivationError.derivationFailed("Failed to encode UTF-8 input")
        }
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    public static let recoverySaltPrefix = "ghost-recovery-salt-v2.0.5:"

    /// Derives deterministic 32-byte recovery_salt from 12-word BIP-39 recovery phrase (Option A)
    public static func deriveRecoverySalt(phrase: String) throws -> Data {
        let words = BIP39.normalize(phrase: phrase)
        guard words.count == 12 else {
            throw RecoveryDerivationError.invalidWordCount(words.count)
        }
        let cleanPhrase = words.joined(separator: " ")
        guard let data = (recoverySaltPrefix + cleanPhrase).data(using: .utf8) else {
            throw RecoveryDerivationError.derivationFailed("Failed to encode UTF-8 input")
        }
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    /// Computes 64-character lowercase hex Argon2id recovery_verifier
    public static func computeRecoveryVerifier(
        authSecret: Data,
        salt: Data,
        memoryKiB: UInt32 = 32768,
        iterations: UInt32 = 3,
        parallelism: UInt32 = 2
    ) throws -> String {
        guard authSecret.count == 32 else {
            throw RecoveryDerivationError.derivationFailed("recovery_auth_secret must be exactly 32 bytes.")
        }
        guard salt.count >= 8 else {
            throw RecoveryDerivationError.derivationFailed("recovery_salt must be at least 8 bytes.")
        }
        
        let secretHex = authSecret.map { String(format: "%02x", $0) }.joined()
        guard let passphraseData = secretHex.data(using: .utf8) else {
            throw RecoveryDerivationError.derivationFailed("Failed to encode hex string as UTF-8 passphrase")
        }

        let verifierRaw = try Argon2idBridge.hash(
            passphrase: passphraseData,
            salt: salt,
            memoryKiB: memoryKiB,
            iterations: iterations,
            parallelism: parallelism,
            hashLength: 32,
            version: 0x13
        )
        return verifierRaw.map { String(format: "%02x", $0) }.joined().lowercased()
    }
}
