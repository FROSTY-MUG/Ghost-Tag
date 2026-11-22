import XCTest
@testable import GhostTagCore

final class RecoveryDerivationTests: XCTestCase {

    // 19. testBIP39NormalizationHandlesExtraWhitespaceAndCasing
    func testBIP39NormalizationHandlesExtraWhitespaceAndCasing() throws {
        let unnormalized = "   ABANDON   ability\n\tABLE about  ABOVE absent\r\nabsorb ABSTRACT absurd ABUSE  access ACCIDENT   "
        let expectedNormalized = "abandon ability able about above absent absorb abstract absurd abuse access accident"

        let normalized = BIP39.normalizedPhraseString(phrase: unnormalized)
        XCTAssertEqual(normalized, expectedNormalized)

        let accountIdFromUnnormalized = try RecoveryDerivation.deriveAccountId(phrase: unnormalized)
        let accountIdFromNormalized = try RecoveryDerivation.deriveAccountId(phrase: expectedNormalized)
        XCTAssertEqual(accountIdFromUnnormalized, accountIdFromNormalized)

        let authSecretFromUnnormalized = try RecoveryDerivation.deriveRecoveryAuthSecret(phrase: unnormalized)
        let authSecretFromNormalized = try RecoveryDerivation.deriveRecoveryAuthSecret(phrase: expectedNormalized)
        XCTAssertEqual(authSecretFromUnnormalized, authSecretFromNormalized)
    }

    // 20. testSupabaseRecoveryPayloadMatchesExpectedJsonSchema
    func testSupabaseRecoveryPayloadMatchesExpectedJsonSchema() throws {
        let testAccountId = UUID(uuidString: "668aca74-6dd2-4e35-a38b-9c9123997810")!
        let testVerifierHex = "5e75bac7805c6a6ebe4df15130f3ddc7f66a6f3530e5198bc8d6852b25859b5f"

        let payload = VaultRecoveryRequest(accountId: testAccountId, recoveryVerifierHex: testVerifierHex)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let jsonData = try encoder.encode(payload)

        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            XCTFail("Failed to encode payload to JSON string")
            return
        }

        let expectedJson = "{\"account_id\":\"668aca74-6dd2-4e35-a38b-9c9123997810\",\"recovery_verifier\":\"5e75bac7805c6a6ebe4df15130f3ddc7f66a6f3530e5198bc8d6852b25859b5f\"}"
        XCTAssertEqual(jsonString, expectedJson)

        // Validate deserialization against expected response schema
        let sampleSuccessResponseJson = """
        {
            "success": true,
            "account_id": "668aca74-6dd2-4e35-a38b-9c9123997810",
            "encrypted_vault_blob": "ZXhhbXBsZS1lbmNyeXB0ZWQtdmF1bHQtYmxvYg==",
            "vault_version": 2
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(VaultRecoveryResponse.self, from: sampleSuccessResponseJson)
        XCTAssertTrue(response.success)
        XCTAssertEqual(response.account_id, "668aca74-6dd2-4e35-a38b-9c9123997810")
        XCTAssertEqual(response.vault_version, 2)
        XCTAssertFalse(response.encrypted_vault_blob.isEmpty)
    }
}
