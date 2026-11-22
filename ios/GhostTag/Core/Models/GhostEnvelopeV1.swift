import Foundation

public struct GhostEnvelopeV1 {
    public static let magic = Data([0x47, 0x54, 0x41, 0x47]) // "GTAG"
    public static let mimeType = "application/vnd.ghost.secure"
    public static let formatVersion: UInt8 = 1
    public static let overheadBytes = 54
    public static let aadBytes = 26

    public let formatVersion: UInt8
    public let purpose: UInt8
    public let keyId: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data
    public let aad: Data

    public init(purpose: UInt8 = 1, keyId: Data, nonce: Data, ciphertext: Data, tag: Data) {
        self.formatVersion = 1
        self.purpose = purpose
        self.keyId = keyId
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
        self.aad = GhostEnvelopeV1.constructAad(purpose: purpose, keyId: keyId, ciphertextLength: UInt32(ciphertext.count))
    }

    public static func constructAad(purpose: UInt8 = 1, keyId: Data, ciphertextLength: UInt32) -> Data {
        var aad = Data()
        aad.append(magic)
        aad.append(formatVersion)
        aad.append(purpose)
        aad.append(keyId)
        var lenLE = ciphertextLength.littleEndian
        withUnsafeBytes(of: &lenLE) { aad.append(contentsOf: $0) }
        return aad
    }

    public func serialize() -> Data {
        var out = Data()
        out.append(GhostEnvelopeV1.magic)
        out.append(formatVersion)
        out.append(purpose)
        out.append(keyId)
        out.append(nonce)
        var lenLE = UInt32(ciphertext.count).littleEndian
        withUnsafeBytes(of: &lenLE) { out.append(contentsOf: $0) }
        out.append(ciphertext)
        out.append(tag)
        return out
    }

    public static func parse(_ data: Data) throws -> GhostEnvelopeV1 {
        guard data.count >= overheadBytes else {
            throw EnvelopeError.insufficientData("Data is smaller than minimum Ghost v1 overhead (\(overheadBytes)B).")
        }
        guard data.prefix(4) == magic else {
            throw EnvelopeError.invalidMagic("THIS TAG TYPE IS NOT SUPPORTED FOR GHOST DATA")
        }
        let version = data[4]
        guard version == formatVersion else {
            throw EnvelopeError.unsupportedVersion("Unsupported envelope version: \(version)")
        }
        let purpose = data[5]
        let keyId = data.subdata(in: 6..<22)
        let nonce = data.subdata(in: 22..<34)
        let lenLE = data.subdata(in: 34..<38).withUnsafeBytes { $0.load(as: UInt32.self) }
        let ciphertextLen = Int(UInt32(littleEndian: lenLE))
        guard data.count == 38 + ciphertextLen + 16 else {
            throw EnvelopeError.dataTruncated("Ciphertext length mismatch with envelope boundary.")
        }
        let ciphertext = data.subdata(in: 38..<(38 + ciphertextLen))
        let tag = data.subdata(in: (38 + ciphertextLen)..<(38 + ciphertextLen + 16))

        return GhostEnvelopeV1(purpose: purpose, keyId: keyId, nonce: nonce, ciphertext: ciphertext, tag: tag)
    }
}
