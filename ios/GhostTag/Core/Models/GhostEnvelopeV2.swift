import Foundation

public struct GhostEnvelopeV2 {
    public static let magic = Data([0x47, 0x54, 0x41, 0x47]) // "GTAG"
    public static let mimeType = "application/vnd.ghost.bulk"
    public static let formatVersion: UInt8 = 2
    public static let recordTypeBulkChunk: UInt8 = 0x10
    public static let overheadBytes = 134
    public static let aadBytes = 74

    public let formatVersion: UInt8
    public let recordType: UInt8
    public let vaultId: Data
    public let fileId: Data
    public let keyId: Data
    public let globalChunkIndex: UInt32
    public let totalVaultChunks: UInt32
    public let fileChunkIndex: UInt32
    public let totalFileChunks: UInt32
    public let chunkHash: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data
    public let aad: Data

    public init(
        recordType: UInt8 = recordTypeBulkChunk,
        vaultId: Data,
        fileId: Data,
        keyId: Data,
        globalChunkIndex: UInt32,
        totalVaultChunks: UInt32,
        fileChunkIndex: UInt32,
        totalFileChunks: UInt32,
        chunkHash: Data,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) {
        self.formatVersion = 2
        self.recordType = recordType
        self.vaultId = vaultId
        self.fileId = fileId
        self.keyId = keyId
        self.globalChunkIndex = globalChunkIndex
        self.totalVaultChunks = totalVaultChunks
        self.fileChunkIndex = fileChunkIndex
        self.totalFileChunks = totalFileChunks
        self.chunkHash = chunkHash
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
        self.aad = GhostEnvelopeV2.constructAad(
            recordType: recordType,
            vaultId: vaultId,
            fileId: fileId,
            keyId: keyId,
            globalChunkIndex: globalChunkIndex,
            totalVaultChunks: totalVaultChunks,
            fileChunkIndex: fileChunkIndex,
            totalFileChunks: totalFileChunks,
            ciphertextLength: UInt32(ciphertext.count)
        )
    }

    public static func constructAad(
        recordType: UInt8 = recordTypeBulkChunk,
        vaultId: Data,
        fileId: Data,
        keyId: Data,
        globalChunkIndex: UInt32,
        totalVaultChunks: UInt32,
        fileChunkIndex: UInt32,
        totalFileChunks: UInt32,
        ciphertextLength: UInt32
    ) -> Data {
        var aad = Data()
        aad.append(magic)
        aad.append(formatVersion)
        aad.append(recordType)
        aad.append(vaultId)
        aad.append(fileId)
        aad.append(keyId)
        var gIndexLE = globalChunkIndex.littleEndian
        withUnsafeBytes(of: &gIndexLE) { aad.append(contentsOf: $0) }
        var tVaultLE = totalVaultChunks.littleEndian
        withUnsafeBytes(of: &tVaultLE) { aad.append(contentsOf: $0) }
        var fIndexLE = fileChunkIndex.littleEndian
        withUnsafeBytes(of: &fIndexLE) { aad.append(contentsOf: $0) }
        var tFileLE = totalFileChunks.littleEndian
        withUnsafeBytes(of: &tFileLE) { aad.append(contentsOf: $0) }
        var cLenLE = ciphertextLength.littleEndian
        withUnsafeBytes(of: &cLenLE) { aad.append(contentsOf: $0) }
        return aad
    }

    public func serialize() -> Data {
        var out = Data()
        out.append(aad)
        out.append(chunkHash)
        out.append(nonce)
        out.append(ciphertext)
        out.append(tag)
        return out
    }

    public static func parse(_ data: Data) throws -> GhostEnvelopeV2 {
        guard data.count >= overheadBytes else {
            throw EnvelopeError.insufficientData("Data is smaller than minimum Ghost v2 overhead (\(overheadBytes)B).")
        }
        guard data.prefix(4) == magic else {
            throw EnvelopeError.invalidMagic("THIS TAG TYPE IS NOT SUPPORTED FOR GHOST DATA")
        }
        let version = data[4]
        guard version == formatVersion else {
            throw EnvelopeError.unsupportedVersion("Unsupported envelope version: \(version)")
        }
        let recordType = data[5]
        guard recordType == recordTypeBulkChunk || recordType == 0x02 else {
            throw EnvelopeError.unsupportedRecordType("Unsupported record type: \(recordType)")
        }

        let vaultId = data.subdata(in: 6..<22)
        let fileId = data.subdata(in: 22..<38)
        let keyId = data.subdata(in: 38..<54)

        let gIndexLE = data.subdata(in: 54..<58).withUnsafeBytes { $0.load(as: UInt32.self) }
        let globalChunkIndex = UInt32(littleEndian: gIndexLE)

        let tVaultLE = data.subdata(in: 58..<62).withUnsafeBytes { $0.load(as: UInt32.self) }
        let totalVaultChunks = UInt32(littleEndian: tVaultLE)

        let fIndexLE = data.subdata(in: 62..<66).withUnsafeBytes { $0.load(as: UInt32.self) }
        let fileChunkIndex = UInt32(littleEndian: fIndexLE)

        let tFileLE = data.subdata(in: 66..<70).withUnsafeBytes { $0.load(as: UInt32.self) }
        let totalFileChunks = UInt32(littleEndian: tFileLE)

        let cLenLE = data.subdata(in: 70..<74).withUnsafeBytes { $0.load(as: UInt32.self) }
        let ciphertextLength = Int(UInt32(littleEndian: cLenLE))

        let chunkHash = data.subdata(in: 74..<106)
        let nonce = data.subdata(in: 106..<118)

        guard data.count == 118 + ciphertextLength + 16 else {
            throw EnvelopeError.dataTruncated("Data was modified or is invalid (truncated ciphertext).")
        }

        let ciphertext = data.subdata(in: 118..<(118 + ciphertextLength))
        let tag = data.subdata(in: (118 + ciphertextLength)..<(118 + ciphertextLength + 16))

        return GhostEnvelopeV2(
            recordType: recordType,
            vaultId: vaultId,
            fileId: fileId,
            keyId: keyId,
            globalChunkIndex: globalChunkIndex,
            totalVaultChunks: totalVaultChunks,
            fileChunkIndex: fileChunkIndex,
            totalFileChunks: totalFileChunks,
            chunkHash: chunkHash,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }
}
