import Foundation

public enum SubscriptionDocumentError: Error, Equatable, Sendable {
    case inputTooLarge
    case invalidUTF8
    case empty
    case htmlDetected
    case invalidBase64
    case decodedTooLarge
}

/// A decoded subscription container: one share link per line.
public struct SubscriptionDocument: Equatable, Sendable {
    public let lines: [String]
    public let wasBase64: Bool

    public init(lines: [String], wasBase64: Bool) {
        self.lines = lines
        self.wasBase64 = wasBase64
    }
}

/// Decodes what a provider returned: a plain text list of share links or a
/// Base64 container holding such a list. No network, no parsing of single
/// links — that stays in `ShareLinkParser`.
public enum SubscriptionDocumentDecoder {
    /// Bound on the decoded payload, after Base64 expansion.
    public static let maximumDecodedBytes = 4_194_304

    private static let base64Alphabet: Set<UInt8> = {
        var set = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-".utf8)
        return set
    }()

    public static func decode(_ data: Data) throws -> SubscriptionDocument {
        guard data.count <= SubscriptionLimits.maximumBytes else {
            throw SubscriptionDocumentError.inputTooLarge
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw SubscriptionDocumentError.invalidUTF8
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw SubscriptionDocumentError.empty
        }
        if isHTML(trimmed) {
            throw SubscriptionDocumentError.htmlDetected
        }
        if let decoded = try tryBase64Container(trimmed) {
            return decoded
        }
        let lines = trimmed
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !lines.isEmpty else {
            throw SubscriptionDocumentError.empty
        }
        return SubscriptionDocument(lines: lines, wasBase64: false)
    }

    private static func isHTML(_ text: String) -> Bool {
        let head = String(text.prefix(1_024)).lowercased()
        return head.hasPrefix("<!doctype") || head.hasPrefix("<html")
    }

    /// Returns a document when the whole payload is one Base64 container.
    /// Returns `nil` when the payload is plain text (a single stray `=` or a
    /// share link is not a container). Single share links contain `@`, `:`,
    /// `/`, `?` outside the Base64 alphabet, so they fall through. Short
    /// alphabet-only strings also fall through — a five-letter paste is a
    /// bad link, not a corrupt container — while a long alphabet-only
    /// payload that cannot decode is reported as `invalidBase64`.
    private static func tryBase64Container(_ text: String) throws -> SubscriptionDocument? {
        let compact = text.filter { !$0.isWhitespace }
        guard !compact.isEmpty,
              compact.utf8.allSatisfy({ base64Alphabet.contains($0) })
        else {
            return nil
        }
        let looksLikeContainer = compact.utf8.count >= 32
        guard compact.utf8.count % 4 != 1 else {
            if looksLikeContainer { throw SubscriptionDocumentError.invalidBase64 }
            return nil
        }
        let standard = compact
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padded = standard + String(repeating: "=", count: (4 - standard.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded, options: .ignoreUnknownCharacters) else {
            if looksLikeContainer { throw SubscriptionDocumentError.invalidBase64 }
            return nil
        }
        guard decoded.count <= maximumDecodedBytes else {
            throw SubscriptionDocumentError.decodedTooLarge
        }
        guard let decodedText = String(data: decoded, encoding: .utf8) else {
            throw SubscriptionDocumentError.invalidBase64
        }
        let lines = decodedText
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !lines.isEmpty else {
            throw SubscriptionDocumentError.invalidBase64
        }
        return SubscriptionDocument(lines: lines, wasBase64: true)
    }
}
