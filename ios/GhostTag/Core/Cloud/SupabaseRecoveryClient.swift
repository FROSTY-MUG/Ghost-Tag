import Foundation

public struct VaultRecoveryRequest: Encodable {
    public let account_id: String
    public let recovery_verifier: String

    public init(accountId: UUID, recoveryVerifierHex: String) {
        self.account_id = accountId.uuidString.lowercased()
        self.recovery_verifier = recoveryVerifierHex.lowercased()
    }
}

public struct VaultRecoveryResponse: Decodable {
    public let success: Bool
    public let account_id: String
    public let encrypted_vault_blob: String
    public let vault_version: Int
}

public struct VaultMigrationRequest: Encodable {
    public let account_id: String
    public let legacy_recovery_verifier: String
    public let new_recovery_verifier: String
    public let recovery_salt: String

    public init(accountId: UUID, legacyVerifierHex: String, newVerifierHex: String, recoverySaltHex: String) {
        self.account_id = accountId.uuidString.lowercased()
        self.legacy_recovery_verifier = legacyVerifierHex.lowercased()
        self.new_recovery_verifier = newVerifierHex.lowercased()
        self.recovery_salt = recoverySaltHex.lowercased()
    }
}

public struct VaultMigrationResponse: Decodable {
    public let success: Bool
    public let recovery_kdf_version: Int
}

public enum SupabaseRecoveryError: Error, LocalizedError {
    case invalidVerifierFormat
    case invalidEndpointUrl
    case networkError(String)
    case recoveryFailed(Int, String)

    public var errorDescription: String? {
        switch self {
        case .invalidVerifierFormat:
            return "Recovery verifier must be exactly 64 hexadecimal characters."
        case .invalidEndpointUrl:
            return "Invalid Supabase endpoint URL."
        case .networkError(let msg):
            return "Network communication error: \(msg)"
        case .recoveryFailed(let code, let msg):
            return "Vault recovery failed (\(code)): \(msg)"
        }
    }
}

public final class SupabaseRecoveryClient {
    public let supabaseUrl: URL
    public let anonKey: String
    private let session: URLSession

    public init(supabaseUrl: URL, anonKey: String, session: URLSession = .shared) {
        self.supabaseUrl = supabaseUrl
        self.anonKey = anonKey
        self.session = session
    }

    /// Calls POST /functions/v1/recover-vault strictly matching Supabase API contract
    public func recoverVault(
        accountId: UUID,
        recoveryVerifierHex: String,
        authToken: String? = nil
    ) async throws -> VaultRecoveryResponse {
        let cleanVerifier = recoveryVerifierHex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let hexPattern = "^[0-9a-f]{64}$"
        guard cleanVerifier.range(of: hexPattern, options: .regularExpression) != nil else {
            throw SupabaseRecoveryError.invalidVerifierFormat
        }

        let endpoint = supabaseUrl.appendingPathComponent("functions/v1/recover-vault")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(anonKey, forHTTPHeaderField: "apikey")
        let bearerToken = authToken ?? anonKey
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")

        let payload = VaultRecoveryRequest(accountId: accountId, recoveryVerifierHex: cleanVerifier)
        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw SupabaseRecoveryError.networkError("Invalid HTTP response")
        }

        guard httpResponse.statusCode == 200 else {
            let errorText = String(data: data, encoding: .utf8) ?? "RECOVERY_FAILED"
            throw SupabaseRecoveryError.recoveryFailed(httpResponse.statusCode, errorText)
        }

        return try JSONDecoder().decode(VaultRecoveryResponse.self, from: data)
    }

    /// Calls POST /functions/v1/migrate-recovery-verifier for zero-knowledge legacy verifier migration
    public func migrateLegacyRecoveryVerifier(
        accountId: UUID,
        legacyVerifierHex: String,
        newVerifierHex: String,
        recoverySaltHex: String,
        authToken: String? = nil
    ) async throws -> VaultMigrationResponse {
        let cleanNewVerifier = newVerifierHex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let cleanLegacyVerifier = legacyVerifierHex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let cleanSalt = recoverySaltHex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let hexPattern = "^[0-9a-f]{64}$"

        guard cleanNewVerifier.range(of: hexPattern, options: .regularExpression) != nil,
              cleanLegacyVerifier.range(of: hexPattern, options: .regularExpression) != nil,
              cleanSalt.range(of: hexPattern, options: .regularExpression) != nil else {
            throw SupabaseRecoveryError.invalidVerifierFormat
        }

        let endpoint = supabaseUrl.appendingPathComponent("functions/v1/migrate-recovery-verifier")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(anonKey, forHTTPHeaderField: "apikey")
        let bearerToken = authToken ?? anonKey
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")

        let payload = VaultMigrationRequest(
            accountId: accountId,
            legacyVerifierHex: cleanLegacyVerifier,
            newVerifierHex: cleanNewVerifier,
            recoverySaltHex: cleanSalt
        )
        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw SupabaseRecoveryError.networkError("Invalid HTTP response")
        }

        guard httpResponse.statusCode == 200 else {
            let errorText = String(data: data, encoding: .utf8) ?? "MIGRATION_FAILED"
            throw SupabaseRecoveryError.recoveryFailed(httpResponse.statusCode, errorText)
        }

        return try JSONDecoder().decode(VaultMigrationResponse.self, from: data)
    }
}
