import Foundation
import XCTest

public extension Data {
    init?(hex: String) {
        let clean = hex.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "0x", with: "")
        guard clean.count % 2 == 0 else { return nil }
        var data = Data()
        var index = clean.startIndex
        while index < clean.endIndex {
            let nextIndex = clean.index(index, offsetBy: 2)
            guard let b = UInt8(clean[index..<nextIndex], radix: 16) else { return nil }
            data.append(b)
            index = nextIndex
        }
        self = data
    }

    func hexString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}

public struct AesGcmVector: Decodable {
    public let id: String
    public let key_hex: String
    public let nonce_hex: String
    public let plaintext_ascii: String
    public let plaintext_hex: String
    public let aad_ascii: String
    public let aad_hex: String
    public let ciphertext_hex: String
    public let tag_hex: String
}

public struct AesGcmFixtureFile: Decodable {
    public let description: String
    public let cipher: String
    public let vectors: [AesGcmVector]
}

public struct RecoveryVector: Decodable {
    public let id: String
    public let words: [String]
    public let phrase: String
    public let account_id: String
    public let recovery_auth_secret_hex: String
    public let recovery_salt_hex: String
    public let recovery_verifier_hex: String
}

public struct RecoveryFixtureFile: Decodable {
    public let description: String
    public let version: String
    public let vectors: [RecoveryVector]
}

public struct V1EnvelopeVector: Decodable {
    public let key_id_hex: String
    public let nonce_hex: String
    public let plaintext_utf8: String
    public let ciphertext_length: Int
    public let ciphertext_hex: String
    public let tag_hex: String
    public let aad_hex: String
    public let serialized_envelope_hex: String
    public let total_envelope_bytes: Int
}

public struct V1EnvelopeFixtureFile: Decodable {
    public let description: String
    public let overhead_bytes: Int
    public let mime: String
    public let vector: V1EnvelopeVector
}

public struct V2BulkEnvelopeVector: Decodable {
    public let vault_id_hex: String
    public let file_id_hex: String
    public let key_id_hex: String
    public let global_chunk_index: UInt32
    public let total_vault_chunks: UInt32
    public let file_chunk_index: UInt32
    public let total_file_chunks: UInt32
    public let plaintext_utf8: String
    public let ciphertext_length: Int
    public let ciphertext_hex: String
    public let chunk_hash_hex: String
    public let nonce_hex: String
    public let tag_hex: String
    public let aad_hex: String
    public let serialized_envelope_hex: String
    public let total_envelope_bytes: Int
}

public struct V2BulkEnvelopeFixtureFile: Decodable {
    public let description: String
    public let overhead_bytes: Int
    public let mime: String
    public let vector: V2BulkEnvelopeVector
}

public enum FixturesLoader {
    private static func findFixtureData(relativePath: String) -> Data? {
        // 1. Try Bundle.module (SwiftPM)
        #if SWIFT_PACKAGE
        if let bundleUrl = Bundle.module.url(forResource: (relativePath as NSString).lastPathComponent, withExtension: nil) {
            if let data = try? Data(contentsOf: bundleUrl) { return data }
        }
        #endif

        // 2. Try file system relative search paths
        let candidates = [
            relativePath,
            "ios/GhostTagTests/Fixtures/" + relativePath,
            "GhostTagTests/Fixtures/" + relativePath,
            "test-fixtures/" + relativePath,
            "../test-fixtures/" + relativePath,
            "../../test-fixtures/" + relativePath
        ]
        for path in candidates {
            if FileManager.default.fileExists(atPath: path), let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                return data
            }
        }
        return nil
    }

    public static func loadAesGcmVectors() -> AesGcmFixtureFile {
        guard let data = findFixtureData(relativePath: "crypto/aesGcmVectors.json"),
              let file = try? JSONDecoder().decode(AesGcmFixtureFile.self, from: data) else {
            fatalError("Could not locate or decode aesGcmVectors.json")
        }
        return file
    }

    public static func loadRecoveryVectors() -> RecoveryFixtureFile {
        guard let data = findFixtureData(relativePath: "recovery/recoveryVectors.json"),
              let file = try? JSONDecoder().decode(RecoveryFixtureFile.self, from: data) else {
            fatalError("Could not locate or decode recoveryVectors.json")
        }
        return file
    }

    public static func loadV1EnvelopeVectors() -> V1EnvelopeFixtureFile {
        guard let data = findFixtureData(relativePath: "envelopes/v1EnvelopeVectors.json"),
              let file = try? JSONDecoder().decode(V1EnvelopeFixtureFile.self, from: data) else {
            fatalError("Could not locate or decode v1EnvelopeVectors.json")
        }
        return file
    }

    public static func loadV2BulkEnvelopeVectors() -> V2BulkEnvelopeFixtureFile {
        guard let data = findFixtureData(relativePath: "envelopes/v2BulkEnvelopeVectors.json"),
              let file = try? JSONDecoder().decode(V2BulkEnvelopeFixtureFile.self, from: data) else {
            fatalError("Could not locate or decode v2BulkEnvelopeVectors.json")
        }
        return file
    }

    public static func loadV1ReferenceBinary() -> Data {
        guard let data = findFixtureData(relativePath: "envelopes/v1-reference.bin") else {
            fatalError("Could not locate v1-reference.bin")
        }
        return data
    }

    public static func loadV2ReferenceBinary() -> Data {
        guard let data = findFixtureData(relativePath: "envelopes/v2-bulk-reference.bin") else {
            fatalError("Could not locate v2-bulk-reference.bin")
        }
        return data
    }
}
