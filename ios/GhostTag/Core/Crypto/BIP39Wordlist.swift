import Foundation

public enum BIP39 {
    /// Normalizes recovery phrase by trimming whitespace, lowercasing, and splitting on any whitespace
    public static func normalize(phrase: String) -> [String] {
        return phrase
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
    }

    /// Returns canonical single-space joined normalized phrase
    public static func normalizedPhraseString(phrase: String) -> String {
        return normalize(phrase: phrase).joined(separator: " ")
    }
}
