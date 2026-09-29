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
/// - Deduplicates by trimmed line (first occurrence wins); duplicates are
///   neither accepted twice nor reported as rejected.
/// - Assigns stable IDs: the same link always maps to the same server ID, so
///   a subscription refresh never loses the user's selected server.
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
            guard seen.insert(line).inserted else { continue }
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

    /// Deterministic ID from the link content alone (FNV-1a, two seeds →
    /// 128 bit). No dependency, same result on every platform and every
    /// launch, independent of line order — which is what keeps the selected
    /// server stable across refreshes. Deduplication by line guarantees
    /// uniqueness within one import.
    public static func stableID(line: String) -> UUID {
        let bytes = Array(line.utf8)
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
