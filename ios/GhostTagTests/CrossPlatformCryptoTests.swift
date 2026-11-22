import XCTest
@testable import GhostTagCore

final class CrossPlatformCryptoTests: XCTestCase {

    // 1. testFixedRecoveryPhraseDerivesExpectedAccountId
    func testFixedRecoveryPhraseDerivesExpectedAccountId() throws {
        let fixtures = FixturesLoader.loadRecoveryVectors()
        for vector in fixtures.vectors {
            let derivedAccountId = try RecoveryDerivation.deriveAccountId(phrase: vector.phrase)
            XCTAssertEqual(
                derivedAccountId.uuidString.lowercased(),
                vector.account_id.lowercased(),
                "Vector \(vector.id) account_id mismatch"
            )
        }
    }

    // 2. testFixedRecoveryPhraseDerivesExpectedRecoveryAuthSecret
    func testFixedRecoveryPhraseDerivesExpectedRecoveryAuthSecret() throws {
        let fixtures = FixturesLoader.loadRecoveryVectors()
        for vector in fixtures.vectors {
            let derivedSecret = try RecoveryDerivation.deriveRecoveryAuthSecret(phrase: vector.phrase)
            XCTAssertEqual(
                derivedSecret.hexString(),
                vector.recovery_auth_secret_hex.lowercased(),
                "Vector \(vector.id) recovery_auth_secret mismatch"
            )
        }
    }

    // 3. testArgon2idRecoveryVerifierMatchesVector
    func testArgon2idRecoveryVerifierMatchesVector() throws {
        let fixtures = FixturesLoader.loadRecoveryVectors()
        for vector in fixtures.vectors {
            guard let authSecret = Data(hex: vector.recovery_auth_secret_hex),
                  let salt = Data(hex: vector.recovery_salt_hex) else {
                XCTFail("Failed to parse hex vector data for \(vector.id)")
                return
            }
            let derivedSalt = try RecoveryDerivation.deriveRecoverySalt(phrase: vector.phrase)
            XCTAssertEqual(derivedSalt.hexString(), vector.recovery_salt_hex.lowercased(), "Vector \(vector.id) recovery_salt mismatch")

            let verifierHex = try RecoveryDerivation.computeRecoveryVerifier(
                authSecret: authSecret,
                salt: salt,
                memoryKiB: 32768,
                iterations: 3,
                parallelism: 2
            )
            XCTAssertEqual(
                verifierHex,
                vector.recovery_verifier_hex.lowercased(),
                "Vector \(vector.id) recovery_verifier mismatch"
            )
        }
    }

    // 4. testArgon2idRejectsWrongSalt
    func testArgon2idRejectsWrongSalt() throws {
        let fixtures = FixturesLoader.loadRecoveryVectors()
        let vector = fixtures.vectors[0]
        guard let authSecret = Data(hex: vector.recovery_auth_secret_hex),
              let wrongSalt = Data(hex: "0000000000000000000000000000000000000000000000000000000000000000") else {
            XCTFail("Failed to parse hex data")
            return
        }
        let differentVerifier = try RecoveryDerivation.computeRecoveryVerifier(
            authSecret: authSecret,
            salt: wrongSalt,
            memoryKiB: 32768,
            iterations: 3,
            parallelism: 2
        )
        XCTAssertNotEqual(
            differentVerifier,
            vector.recovery_verifier_hex.lowercased(),
            "Argon2id must produce different verifier for different salt"
        )
    }

    // 5. testArgon2idRejectsDifferentIterations
    func testArgon2idRejectsDifferentIterations() throws {
        let fixtures = FixturesLoader.loadRecoveryVectors()
        let vector = fixtures.vectors[0]
        guard let authSecret = Data(hex: vector.recovery_auth_secret_hex),
              let salt = Data(hex: vector.recovery_salt_hex) else {
            XCTFail("Failed to parse hex data")
            return
        }
        let differentVerifier = try RecoveryDerivation.computeRecoveryVerifier(
            authSecret: authSecret,
            salt: salt,
            memoryKiB: 32768,
            iterations: 2, // Changed from 3
            parallelism: 2
        )
        XCTAssertNotEqual(differentVerifier, vector.recovery_verifier_hex.lowercased())
    }

    // 6. testArgon2idRejectsDifferentMemory
    func testArgon2idRejectsDifferentMemory() throws {
        let fixtures = FixturesLoader.loadRecoveryVectors()
        let vector = fixtures.vectors[0]
        guard let authSecret = Data(hex: vector.recovery_auth_secret_hex),
              let salt = Data(hex: vector.recovery_salt_hex) else {
            XCTFail("Failed to parse hex data")
            return
        }
        let differentVerifier = try RecoveryDerivation.computeRecoveryVerifier(
            authSecret: authSecret,
            salt: salt,
            memoryKiB: 16384, // Changed from 32768
            iterations: 3,
            parallelism: 2
        )
        XCTAssertNotEqual(differentVerifier, vector.recovery_verifier_hex.lowercased())
    }

    // 7. testArgon2idRejectsDifferentParallelism
    func testArgon2idRejectsDifferentParallelism() throws {
        let fixtures = FixturesLoader.loadRecoveryVectors()
        let vector = fixtures.vectors[0]
        guard let authSecret = Data(hex: vector.recovery_auth_secret_hex),
              let salt = Data(hex: vector.recovery_salt_hex) else {
            XCTFail("Failed to parse hex data")
            return
        }
        let differentVerifier = try RecoveryDerivation.computeRecoveryVerifier(
            authSecret: authSecret,
            salt: salt,
            memoryKiB: 32768,
            iterations: 3,
            parallelism: 1 // Changed from 2
        )
        XCTAssertNotEqual(differentVerifier, vector.recovery_verifier_hex.lowercased())
    }

    // 8. testAes256GcmEncryptDecryptRoundTrip
    func testAes256GcmEncryptDecryptRoundTrip() throws {
        let fixtures = FixturesLoader.loadAesGcmVectors()
        for vector in fixtures.vectors {
            guard let key = Data(hex: vector.key_hex),
                  let nonce = Data(hex: vector.nonce_hex),
                  let plaintext = Data(hex: vector.plaintext_hex),
                  let aad = Data(hex: vector.aad_hex),
                  let expectedCiphertext = Data(hex: vector.ciphertext_hex),
                  let expectedTag = Data(hex: vector.tag_hex) else {
                XCTFail("Failed to parse hex AES-GCM vector \(vector.id)")
                return
            }

            let encrypted = try GhostTagCrypto.encrypt(key: key, plaintext: plaintext, nonce: nonce, aad: aad)
            XCTAssertEqual(encrypted.ciphertext.hexString(), expectedCiphertext.hexString())
            XCTAssertEqual(encrypted.tag.hexString(), expectedTag.hexString())

            let decrypted = try GhostTagCrypto.decrypt(
                key: key,
                ciphertext: encrypted.ciphertext,
                nonce: encrypted.nonce,
                tag: encrypted.tag,
                aad: aad
            )
            XCTAssertEqual(decrypted, plaintext)
        }
    }

    // 9. testAes256GcmRejectsTamperedCiphertext
    func testAes256GcmRejectsTamperedCiphertext() throws {
        let fixtures = FixturesLoader.loadAesGcmVectors()
        let vector = fixtures.vectors[0]
        guard let key = Data(hex: vector.key_hex),
              let nonce = Data(hex: vector.nonce_hex),
              var tamperedCiphertext = Data(hex: vector.ciphertext_hex),
              let tag = Data(hex: vector.tag_hex),
              let aad = Data(hex: vector.aad_hex) else {
            XCTFail("Failed to parse hex data")
            return
        }
        tamperedCiphertext[0] ^= 0x01 // Flip one bit

        XCTAssertThrowsError(
            try GhostTagCrypto.decrypt(key: key, ciphertext: tamperedCiphertext, nonce: nonce, tag: tag, aad: aad),
            "Decryption must fail when ciphertext is modified"
        )
    }

    // 10. testAes256GcmRejectsTamperedTag
    func testAes256GcmRejectsTamperedTag() throws {
        let fixtures = FixturesLoader.loadAesGcmVectors()
        let vector = fixtures.vectors[0]
        guard let key = Data(hex: vector.key_hex),
              let nonce = Data(hex: vector.nonce_hex),
              let ciphertext = Data(hex: vector.ciphertext_hex),
              var tamperedTag = Data(hex: vector.tag_hex),
              let aad = Data(hex: vector.aad_hex) else {
            XCTFail("Failed to parse hex data")
            return
        }
        tamperedTag[0] ^= 0x01 // Flip one bit

        XCTAssertThrowsError(
            try GhostTagCrypto.decrypt(key: key, ciphertext: ciphertext, nonce: nonce, tag: tamperedTag, aad: aad),
            "Decryption must fail when authentication tag is modified"
        )
    }

    // 11. testAes256GcmRejectsTamperedAad
    func testAes256GcmRejectsTamperedAad() throws {
        let fixtures = FixturesLoader.loadAesGcmVectors()
        let vector = fixtures.vectors[0]
        guard let key = Data(hex: vector.key_hex),
              let nonce = Data(hex: vector.nonce_hex),
              let ciphertext = Data(hex: vector.ciphertext_hex),
              let tag = Data(hex: vector.tag_hex),
              var tamperedAad = Data(hex: vector.aad_hex) else {
            XCTFail("Failed to parse hex data")
            return
        }
        tamperedAad[0] ^= 0x01 // Flip one bit

        XCTAssertThrowsError(
            try GhostTagCrypto.decrypt(key: key, ciphertext: ciphertext, nonce: nonce, tag: tag, aad: tamperedAad),
            "Decryption must fail when AAD is modified"
        )
    }

    // 12. testAes256GcmRejectsWrongKey
    func testAes256GcmRejectsWrongKey() throws {
        let fixtures = FixturesLoader.loadAesGcmVectors()
        let vector = fixtures.vectors[0]
        guard var wrongKey = Data(hex: vector.key_hex),
              let nonce = Data(hex: vector.nonce_hex),
              let ciphertext = Data(hex: vector.ciphertext_hex),
              let tag = Data(hex: vector.tag_hex),
              let aad = Data(hex: vector.aad_hex) else {
            XCTFail("Failed to parse hex data")
            return
        }
        wrongKey[0] ^= 0xff

        XCTAssertThrowsError(
            try GhostTagCrypto.decrypt(key: wrongKey, ciphertext: ciphertext, nonce: nonce, tag: tag, aad: aad),
            "Decryption must fail with an incorrect key"
        )
    }
}
