import Foundation

public struct VaultMetadata: Codable, Equatable {
    public let accountId: UUID
    public let vaultVersion: Int
    public let saltHex: String
    public var recoveryVerifierHex: String?
    public var recoverySaltHex: String?
    public var recoveryKdfVersion: Int?
    public var encryptedBlobBase64: String?
    public var updatedAt: Date

    enum CodingKeys: String, CodingKey {
        case accountId = "account_id"
        case vaultVersion = "vault_version"
        case saltHex = "salt_hex"
        case recoveryVerifierHex = "recovery_verifier_hex"
        case recoverySaltHex = "recovery_salt_hex"
        case recoveryKdfVersion = "recovery_kdf_version"
        case encryptedBlobBase64 = "encrypted_vault_blob"
        case updatedAt = "updated_at"
    }

    public init(
        accountId: UUID,
        vaultVersion: Int = 2,
        saltHex: String,
        recoveryVerifierHex: String? = nil,
        recoverySaltHex: String? = nil,
        recoveryKdfVersion: Int? = 2,
        encryptedBlobBase64: String? = nil,
        updatedAt: Date = Date()
    ) {
        self.accountId = accountId
        self.vaultVersion = vaultVersion
        self.saltHex = saltHex
        self.recoveryVerifierHex = recoveryVerifierHex
        self.recoverySaltHex = recoverySaltHex
        self.recoveryKdfVersion = recoveryKdfVersion
        self.encryptedBlobBase64 = encryptedBlobBase64
        self.updatedAt = updatedAt
    }
}
