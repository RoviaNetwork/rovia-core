import Foundation
import RoviaConfig

/// One line the importer refused. The raw line is never stored: share links
/// carry passwords, and a rejection reason plus the 1-based line number is
/// all the UI needs to say "line 3: unsupported scheme".
public struct RejectedSubscriptionLine: Equatable, Sendable {
    public let index: Int
    public let reason: ShareLinkParseError

    public init(index: Int, reason: ShareLinkParseError) {
        self.index = index
        self.reason = reason
    }
}

public struct SubscriptionImportResult: Equatable, Sendable {
    public let accepted: [ParsedShareLink]
    public let rejected: [RejectedSubscriptionLine]

    public init(accepted: [ParsedShareLink], rejected: [RejectedSubscriptionLine]) {
        self.accepted = accepted
        self.rejected = rejected
    }
}

/// Turns decoded document lines into parsed servers with honest counts.
///
/// - Deduplicates by canonical line (first occurrence wins); cosmetic
///   duplicates — same link with a fragment renamed, query reordered, or
///   scheme/host recased — collapse to one server, because they were already
///   indistinguishable downstream.
/// - Assigns stable IDs from the canonical line: a cosmetic edit never resets
///   the user's selected server. Passwords, paths, and ports stay
///   case-sensitive: only the scheme and the host are case-insensitive, and
///   only the fragment is dropped.
/// - Never throws: every failure lands in `rejected` with its typed reason.
///   An empty result (no lines) yields an empty `SubscriptionImportResult`.
public enum SubscriptionImporter {
    public static func importLines(
        _ lines: [String],
        credentialSink: ShareLinkCredentialSink,
        idForLine: (String) -> UUID = { stableID(line: $0) }
    ) -> SubscriptionImportResult {
        var seen: Set<String> = []
        var accepted: [ParsedShareLink] = []
        var rejected: [RejectedSubscriptionLine] = []
        for (offset, rawLine) in lines.enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            let canonical = canonicalLine(line)
            guard seen.insert(canonical).inserted else { continue }
            do {
                let parsed = try ShareLinkParser.parse(
                    Data(line.utf8),
                    id: idForLine(line),
                    credentialSink: credentialSink
                )
                accepted.append(parsed)
            } catch let error as ShareLinkParseError {
                rejected.append(RejectedSubscriptionLine(index: offset + 1, reason: error))
            } catch {
                rejected.append(RejectedSubscriptionLine(index: offset + 1, reason: .malformedURL))
            }
        }
        return SubscriptionImportResult(accepted: accepted, rejected: rejected)
    }

    /// Canonical form of a share-link line for identity and deduplication.
    ///
    /// Normalizes exactly the parts the parser treats as insignificant:
    /// surrounding whitespace, the `#fragment` (a display remark the parser
    /// drops), query-parameter order, and the case of the scheme and the
    /// host. Everything else — userinfo (passwords are case-sensitive),
    /// port, path, and query values — is preserved byte-for-byte, so two
    /// lines that canonicalize equally always parse to the same server.
    public static func canonicalLine(_ line: String) -> String {
        var text = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if let hash = text.firstIndex(of: "#") {
            text = String(text[..<hash])
        }
        guard let schemeRange = text.range(of: "://") else {
            return text
        }
        let scheme = text[..<schemeRange.lowerBound].lowercased()
        var rest = String(text[schemeRange.upperBound...])
        var query = ""
        if let question = rest.firstIndex(of: "?") {
            query = String(rest[rest.index(after: question)...])
            rest = String(rest[..<question])
        }
        rest = lowercasedHost(in: rest) + ""
        if !query.isEmpty {
            let pairs = query.split(separator: "&", omittingEmptySubsequences: true).map(String.init)
            query = "?" + pairs.sorted().joined(separator: "&")
        }
        return scheme + "://" + rest + query
    }

    /// Lowercases the host inside `userinfo@host:port`, `[v6]:port`, or
    /// `host:port` authority forms. Userinfo, brackets, and port are
    /// preserved exactly; an unparseable authority is returned unchanged and
    /// left for the parser to reject with its typed error.
    private static func lowercasedHost(in authority: String) -> String {
        let hostAndPort: String
        let userinfoPrefix: String
        if let at = authority.lastIndex(of: "@") {
            userinfoPrefix = String(authority[...at])
            hostAndPort = String(authority[authority.index(after: at)...])
        } else {
            userinfoPrefix = ""
            hostAndPort = authority
        }
        if hostAndPort.hasPrefix("[") {
            guard let close = hostAndPort.firstIndex(of: "]") else { return authority }
            let host = String(hostAndPort[hostAndPort.index(after: hostAndPort.startIndex)..<close]).lowercased()
            return userinfoPrefix + "[" + host + "]" + String(hostAndPort[hostAndPort.index(after: close)...])
        }
        guard let colon = hostAndPort.lastIndex(of: ":") else {
            return userinfoPrefix + hostAndPort.lowercased()
        }
        let host = String(hostAndPort[..<colon]).lowercased()
        return userinfoPrefix + host + String(hostAndPort[colon...])
    }

    /// Deterministic ID from the canonical link content (FNV-1a, two seeds →
    /// 128 bit). No dependency, same result on every platform and every
    /// launch, independent of line order and cosmetic edits — which is what
    /// keeps the selected server stable across refreshes. Deduplication by
    /// canonical line guarantees uniqueness within one import.
    ///
    /// Version history: v1 hashed the raw line; v2 (this) hashes
    /// `canonicalLine`. Stored v1 IDs rotate once on the next refresh; the
    /// store's `schemaVersion` records which side a record is on.
    public static func stableID(line: String) -> UUID {
        let bytes = Array(canonicalLine(line).utf8)
        var halves: [UInt64] = []
        for seed in [UInt64(0xCBF29CE484222325), UInt64(0x84222325CBF29CE4)] {
            var hash = seed
            for byte in bytes {
                hash ^= UInt64(byte)
                hash &*= 0x100000001B3
            }
            halves.append(hash)
        }
        let hex = halves.map { String(format: "%016llx", $0) }.joined()
        let uuidString = "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20).prefix(12))"
        return UUID(uuidString: String(uuidString)) ?? UUID()
    }
}
