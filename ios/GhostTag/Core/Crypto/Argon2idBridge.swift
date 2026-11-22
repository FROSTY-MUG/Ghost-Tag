import Foundation
import Clibargon2

public enum Argon2Error: Error, LocalizedError {
    case derivationFailed(Int32, String)
    case invalidParameters(String)

    public var errorDescription: String? {
        switch self {
        case .derivationFailed(let code, let msg):
            return "Argon2 derivation failed with error code \(code): \(msg)"
        case .invalidParameters(let msg):
            return "Invalid Argon2 parameters: \(msg)"
        }
    }
}

public enum Argon2idBridge {
    public static func hash(
        passphrase: Data,
        salt: Data,
        memoryKiB: UInt32 = 32768,
        iterations: UInt32 = 3,
        parallelism: UInt32 = 2,
        hashLength: UInt32 = 32,
        version: UInt32 = 0x13
    ) throws -> Data {
        guard salt.count >= 8 else {
            throw Argon2Error.invalidParameters("Salt must be at least 8 bytes.")
        }
        guard hashLength > 0 else {
            throw Argon2Error.invalidParameters("Hash length must be greater than 0.")
        }

        var output = Data(count: Int(hashLength))
        let result = output.withUnsafeMutableBytes { outBuf -> Int32 in
            passphrase.withUnsafeBytes { pwdBuf -> Int32 in
                salt.withUnsafeBytes { saltBuf -> Int32 in
                    argon2id_hash_raw(
                        iterations,
                        memoryKiB,
                        parallelism,
                        pwdBuf.baseAddress,
                        passphrase.count,
                        saltBuf.baseAddress,
                        salt.count,
                        outBuf.baseAddress,
                        Int(hashLength)
                    )
                }
            }
        }

        guard result == 0 else {
            let errorMsg = String(cString: argon2_error_message(result))
            throw Argon2Error.derivationFailed(result, errorMsg)
        }

        return output
    }

    public static func hashHex(
        passphrase: Data,
        salt: Data,
        memoryKiB: UInt32 = 32768,
        iterations: UInt32 = 3,
        parallelism: UInt32 = 2,
        hashLength: UInt32 = 32
    ) throws -> String {
        let raw = try hash(
            passphrase: passphrase,
            salt: salt,
            memoryKiB: memoryKiB,
            iterations: iterations,
            parallelism: parallelism,
            hashLength: hashLength
        )
        return raw.map { String(format: "%02x", $0) }.joined()
    }
}
