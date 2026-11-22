import Foundation

public enum EnvelopeError: Error, LocalizedError {
    case insufficientData(String)
    case invalidMagic(String)
    case unsupportedVersion(String)
    case unsupportedRecordType(String)
    case dataTruncated(String)
    case chunkHashMismatch
    case authenticationFailed

    public var errorDescription: String? {
        switch self {
        case .insufficientData(let msg): return msg
        case .invalidMagic(let msg): return msg
        case .unsupportedVersion(let msg): return msg
        case .unsupportedRecordType(let msg): return msg
        case .dataTruncated(let msg): return msg
        case .chunkHashMismatch: return "Integrity check failed: chunk SHA-256 hash mismatch."
        case .authenticationFailed: return "Envelope decryption failed: authentication tag verification error."
        }
    }
}

public enum EnvelopeCodec {
    /// Encrypts and encodes a v1 single-tag envelope (54-byte overhead, 26-byte AAD)
    public static func encodeV1(
        key: Data,
        keyId: Data,
        plaintext: Data,
        purpose: UInt8 = 1,
        nonce: Data? = nil
    ) throws -> Data {
        let aad = GhostEnvelopeV1.constructAad(purpose: purpose, keyId: keyId, ciphertextLength: UInt32(plaintext.count))
        let enc = try GhostTagCrypto.encrypt(key: key, plaintext: plaintext, nonce: nonce, aad: aad)
        let env = GhostEnvelopeV1(purpose: purpose, keyId: keyId, nonce: enc.nonce, ciphertext: enc.ciphertext, tag: enc.tag)
        return env.serialize()
    }

    /// Decodes and decrypts a v1 single-tag envelope
    public static func decodeV1(key: Data, data: Data) throws -> Data {
        let env = try GhostEnvelopeV1.parse(data)
        return try GhostTagCrypto.decrypt(key: key, ciphertext: env.ciphertext, nonce: env.nonce, tag: env.tag, aad: env.aad)
    }

    /// Encrypts and encodes a v2 bulk envelope chunk (134-byte overhead, 74-byte AAD, recordType 0x10)
    public static func encodeV2(
        key: Data,
        vaultId: Data,
        fileId: Data,
        keyId: Data,
        globalChunkIndex: UInt32,
        totalVaultChunks: UInt32,
        fileChunkIndex: UInt32,
        totalFileChunks: UInt32,
        plaintextChunk: Data,
        recordType: UInt8 = GhostEnvelopeV2.recordTypeBulkChunk,
        nonce: Data? = nil
    ) throws -> Data {
        let chunkHash = GhostTagCrypto.sha256(plaintextChunk)
        let aad = GhostEnvelopeV2.constructAad(
            recordType: recordType,
            vaultId: vaultId,
            fileId: fileId,
            keyId: keyId,
            globalChunkIndex: globalChunkIndex,
            totalVaultChunks: totalVaultChunks,
            fileChunkIndex: fileChunkIndex,
            totalFileChunks: totalFileChunks,
            ciphertextLength: UInt32(plaintextChunk.count)
        )
        let enc = try GhostTagCrypto.encrypt(key: key, plaintext: plaintextChunk, nonce: nonce, aad: aad)
        let env = GhostEnvelopeV2(
            recordType: recordType,
            vaultId: vaultId,
            fileId: fileId,
            keyId: keyId,
            globalChunkIndex: globalChunkIndex,
            totalVaultChunks: totalVaultChunks,
            fileChunkIndex: fileChunkIndex,
            totalFileChunks: totalFileChunks,
            chunkHash: chunkHash,
            nonce: enc.nonce,
            ciphertext: enc.ciphertext,
            tag: enc.tag
        )
        return env.serialize()
    }

    /// Decodes, verifies chunk SHA-256 hash, and decrypts a v2 bulk envelope chunk
    public static func decodeV2(key: Data, data: Data) throws -> Data {
        let env = try GhostEnvelopeV2.parse(data)
        let plaintext = try GhostTagCrypto.decrypt(key: key, ciphertext: env.ciphertext, nonce: env.nonce, tag: env.tag, aad: env.aad)
        let computedHash = GhostTagCrypto.sha256(plaintext)
        guard computedHash == env.chunkHash else {
            throw EnvelopeError.chunkHashMismatch
        }
        return plaintext
    }
}
