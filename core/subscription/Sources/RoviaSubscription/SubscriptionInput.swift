import Foundation

/// The entry kinds Rovia accepts from the user.
///
/// A subscription URL (`http://`/`https://`) and a single-server share link
/// (`vless://`, `trojan://`, `ss://`) are different inputs: the first is
/// downloaded, the second is parsed directly. HTTPS inside `ShareLinkParser`
/// stays rejected — fetching is the fetcher's job, not the parser's.
public enum SubscriptionInputKind: Equatable, Sendable {
    case singleShareLink(scheme: ShareLinkScheme)
    case subscriptionURL(URL)
    case pastedText
}

public enum ShareLinkScheme: String, Equatable, Sendable {
    case vless
    case trojan
    case ss
}

/// Classifies raw user input without touching the network.
///
/// Never throws: anything that is not a recognizable single link or URL is
/// `pastedText`, and the decoder/importer below report the exact reason.
/// Returns `nil` only for empty input.
public enum SubscriptionInputClassifier {
    public static func classify(_ rawText: String) -> SubscriptionInputKind? {
        let trimmed = rawText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        // A multi-line paste is a container, never a single link or URL.
        guard !trimmed.contains(where: { $0 == "\n" || $0 == "\r" }) else {
            return .pastedText
        }
        if let scheme = ShareLinkScheme(rawValue: schemePrefix(of: trimmed)) {
            return .singleShareLink(scheme: scheme)
        }
        if let url = subscriptionURL(from: trimmed) {
            return .subscriptionURL(url)
        }
        return .pastedText
    }

    private static func schemePrefix(of line: String) -> String {
        guard let range = line.range(of: "://") else { return "" }
        return String(line[..<range.lowerBound]).lowercased()
    }

    private static func subscriptionURL(from line: String) -> URL? {
        guard let url = URL(string: line),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.host != nil
        else {
            return nil
        }
        return url
    }
}
