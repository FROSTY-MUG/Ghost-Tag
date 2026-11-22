import XCTest
@testable import GhostTagCore

final class EnvelopeCodecTests: XCTestCase {

    // 13. testV1EnvelopeEncodingMatchesReference
    func testV1EnvelopeEncodingMatchesReference() throws {
        let fixture = FixturesLoader.loadV1EnvelopeVectors()
        let refBinary = FixturesLoader.loadV1ReferenceBinary()
        let vector = fixture.vector

        guard let keyId = Data(hex: vector.key_id_hex),
              let nonce = Data(hex: vector.nonce_hex),
              let ciphertext = Data(hex: vector.ciphertext_hex),
              let tag = Data(hex: vector.tag_hex),
              let expectedSerialized = Data(hex: vector.serialized_envelope_hex) else {
            XCTFail("Failed to parse hex data in v1 vector")
            return
        }

        let envelope = GhostEnvelopeV1(purpose: 1, keyId: keyId, nonce: nonce, ciphertext: ciphertext, tag: tag)
        let serialized = envelope.serialize()

        XCTAssertEqual(serialized, expectedSerialized)
        XCTAssertEqual(serialized, refBinary)
        XCTAssertEqual(serialized.count, fixture.overhead_bytes + ciphertext.count)
        XCTAssertEqual(envelope.aad.count, fixture.vector.aad_hex.count / 2)
    }

    // 14. testV1EnvelopeDecodingValidPayload
    func testV1EnvelopeDecodingValidPayload() throws {
        let fixture = FixturesLoader.loadV1EnvelopeVectors()
        let vector = fixture.vector
        guard let serialized = Data(hex: vector.serialized_envelope_hex),
              let expectedCiphertext = Data(hex: vector.ciphertext_hex) else {
            XCTFail("Failed to parse hex serialized envelope")
            return
        }

        let parsed = try GhostEnvelopeV1.parse(serialized)
        XCTAssertEqual(parsed.formatVersion, 1)
        XCTAssertEqual(parsed.purpose, 1)
        XCTAssertEqual(parsed.ciphertext, expectedCiphertext)
        XCTAssertEqual(parsed.aad.hexString(), vector.aad_hex.lowercased())
    }

    // 15. testV1EnvelopeRejectsCorruptedHeader
    func testV1EnvelopeRejectsCorruptedHeader() throws {
        let fixture = FixturesLoader.loadV1EnvelopeVectors()
        guard var corrupted = Data(hex: fixture.vector.serialized_envelope_hex) else {
            XCTFail("Failed to parse hex")
            return
        }
        // Corrupt magic bytes from "GTAG" to "XTAG"
        corrupted[0] = 0x58

        XCTAssertThrowsError(try GhostEnvelopeV1.parse(corrupted)) { error in
            guard let envError = error as? EnvelopeError else {
                XCTFail("Expected EnvelopeError, received \(error)")
                return
            }
            if case .invalidMagic = envError {
                // Expected
            } else {
                XCTFail("Expected invalidMagic error, got \(envError)")
            }
        }
    }

    // 16. testV2BulkEnvelopeEncodingMatchesReference
    func testV2BulkEnvelopeEncodingMatchesReference() throws {
        let fixture = FixturesLoader.loadV2BulkEnvelopeVectors()
        let refBinary = FixturesLoader.loadV2ReferenceBinary()
        let vector = fixture.vector

        guard let vaultId = Data(hex: vector.vault_id_hex),
              let fileId = Data(hex: vector.file_id_hex),
              let keyId = Data(hex: vector.key_id_hex),
              let chunkHash = Data(hex: vector.chunk_hash_hex),
              let nonce = Data(hex: vector.nonce_hex),
              let ciphertext = Data(hex: vector.ciphertext_hex),
              let tag = Data(hex: vector.tag_hex),
              let expectedSerialized = Data(hex: vector.serialized_envelope_hex) else {
            XCTFail("Failed to parse hex data in v2 bulk vector")
            return
        }

        let envelope = GhostEnvelopeV2(
            recordType: 0x10,
            vaultId: vaultId,
            fileId: fileId,
            keyId: keyId,
            globalChunkIndex: vector.global_chunk_index,
            totalVaultChunks: vector.total_vault_chunks,
            fileChunkIndex: vector.file_chunk_index,
            totalFileChunks: vector.total_file_chunks,
            chunkHash: chunkHash,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
        let serialized = envelope.serialize()

        XCTAssertEqual(serialized, expectedSerialized)
        XCTAssertEqual(serialized, refBinary)
        XCTAssertEqual(serialized.count, fixture.overhead_bytes + ciphertext.count)
        XCTAssertEqual(envelope.aad.count, fixture.aad_bytes)
    }

    // 17. testV2BulkEnvelopeDecodingValidPayload
    func testV2BulkEnvelopeDecodingValidPayload() throws {
        let fixture = FixturesLoader.loadV2BulkEnvelopeVectors()
        let vector = fixture.vector
        guard let serialized = Data(hex: vector.serialized_envelope_hex),
              let expectedCiphertext = Data(hex: vector.ciphertext_hex) else {
            XCTFail("Failed to parse hex serialized envelope")
            return
        }

        let parsed = try GhostEnvelopeV2.parse(serialized)
        XCTAssertEqual(parsed.formatVersion, 2)
        XCTAssertEqual(parsed.recordType, 0x10)
        XCTAssertEqual(parsed.ciphertext, expectedCiphertext)
        XCTAssertEqual(parsed.aad.hexString(), vector.aad_hex.lowercased())
    }

    // 18. testV2BulkEnvelopeRejectsChunkHashMismatch
    func testV2BulkEnvelopeRejectsChunkHashMismatch() throws {
        let fixture = FixturesLoader.loadV2BulkEnvelopeVectors()
        let vector = fixture.vector
        guard let key = Data(hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
              let vaultId = Data(hex: vector.vault_id_hex),
              let fileId = Data(hex: vector.file_id_hex),
              let keyId = Data(hex: vector.key_id_hex) else {
            XCTFail("Failed to parse hex keys")
            return
        }
        guard let plaintext = vector.plaintext_utf8.data(using: .utf8) else {
            XCTFail("Failed to encode plaintext")
            return
        }

        let encoded = try EnvelopeCodec.encodeV2(
            key: key,
            vaultId: vaultId,
            fileId: fileId,
            keyId: keyId,
            globalChunkIndex: 0,
            totalVaultChunks: 1,
            fileChunkIndex: 0,
            totalFileChunks: 1,
            plaintextChunk: plaintext
        )

        // Parse and corrupt the chunk_hash field (bytes 74..<106)
        var corrupted = encoded
        corrupted[74] ^= 0xff

        XCTAssertThrowsError(try EnvelopeCodec.decodeV2(key: key, data: corrupted)) { error in
            guard let envError = error as? EnvelopeError else {
                XCTFail("Expected EnvelopeError, received \(error)")
                return
            }
            if case .chunkHashMismatch = envError {
                // Expected
            } else {
                XCTFail("Expected chunkHashMismatch error, got \(envError)")
            }
        }
    }
}
