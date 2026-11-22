import Foundation
import CryptoKit

public enum GhostTagCryptoError: Error, LocalizedError {
    case invalidKeyLength(Int)
    case invalidNonceLength(Int)
    case invalidTagLength(Int)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case authenticationTagMismatch
    
    public var errorDescription: String? {
        switch self {
        case .invalidKeyLength(let len):
            return "AES-256-GCM key must be exactly 32 bytes (received \(len) bytes)."
        case .invalidNonceLength(let len):
            return "AES-256-GCM nonce must be exactly 12 bytes (received \(len) bytes)."
        case .invalidTagLength(let len):
            return "AES-256-GCM authentication tag must be exactly 16 bytes (received \(len) bytes)."
        case .encryptionFailed(let msg):
            return "Encryption failed: \(msg)"
        case .decryptionFailed(let msg):
            return "Decryption failed: \(msg)"
        case .authenticationTagMismatch:
            return "Decryption failed: authentication tag mismatch or corrupted ciphertext/AAD."
        }
    }
}

public enum GhostTagCrypto {
    public static let keyLength = 32
    public static let nonceLength = 12
    public static let tagLength = 16

    /// Computes SHA-256 digest of data
    public static func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    /// Encrypts plaintext using AES-256-GCM with optional nonce and optional AAD
    public static func encrypt(
        key: Data,
        plaintext: Data,
        nonce: Data? = nil,
        aad: Data? = nil
    ) throws -> (ciphertext: Data, nonce: Data, tag: Data) {
        guard key.count == keyLength else {
            throw GhostTagCryptoError.invalidKeyLength(key.count)
        }
        
        let symmetricKey = SymmetricKey(data: key)
        let gcmNonce: AES.GCM.Nonce
        if let explicitNonce = nonce {
            guard explicitNonce.count == nonceLength else {
                throw GhostTagCryptoError.invalidNonceLength(explicitNonce.count)
            }
            gcmNonce = try AES.GCM.Nonce(data: explicitNonce)
        } else {
            gcmNonce = AES.GCM.Nonce()
        }
        
        do {
            let sealedBox: AES.GCM.SealedBox
            if let authenticating = aad, !authenticating.isEmpty {
                sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: gcmNonce, authenticating: authenticating)
            } else {
                sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: gcmNonce)
            }
            return (ciphertext: sealedBox.ciphertext, nonce: Data(sealedBox.nonce), tag: sealedBox.tag)
        } catch {
            throw GhostTagCryptoError.encryptionFailed(error.localizedDescription)
        }
    }

    /// Decrypts ciphertext using AES-256-GCM with explicit nonce, tag, and optional AAD
    public static func decrypt(
        key: Data,
        ciphertext: Data,
        nonce: Data,
        tag: Data,
        aad: Data? = nil
    ) throws -> Data {
        guard key.count == keyLength else {
            throw GhostTagCryptoError.invalidKeyLength(key.count)
        }
        guard nonce.count == nonceLength else {
            throw GhostTagCryptoError.invalidNonceLength(nonce.count)
        }
        guard tag.count == tagLength else {
            throw GhostTagCryptoError.invalidTagLength(tag.count)
        }

        let symmetricKey = SymmetricKey(data: key)
        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
            if let authenticating = aad, !authenticating.isEmpty {
                return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: authenticating)
            } else {
                return try AES.GCM.open(sealedBox, using: symmetricKey)
            }
        } catch {
            throw GhostTagCryptoError.authenticationTagMismatch
        }
    }
}
