import Foundation
import RoviaConfig

public enum SubscriptionImportError: Error, Equatable, Sendable {
    case inputTooLarge
    case invalidUTF8
}

public enum SubscriptionLimits {
    public static let maximumBytes = 1_048_576

    public static func validate(_ data: Data) throws {
        guard data.count <= maximumBytes else {
            throw SubscriptionImportError.inputTooLarge
        }
        guard String(data: data, encoding: .utf8) != nil else {
            throw SubscriptionImportError.invalidUTF8
        }
    }
}

public enum SubscriptionRedactor {
    public static func redactURL(_ value: String) -> String {
        guard let components = URLComponents(string: value), let scheme = components.scheme, let host = components.host else {
            return "redacted"
        }
        let port = components.port.map { ":\($0)" } ?? ""
        return "\(scheme)://\(host)\(port)/••••••••"
    }

    public static func redactShareLink(protocolKind: ProxyProtocol, host: String, port: Int) -> String {
        guard !host.isEmpty,
              (1...65_535).contains(port),
              !host.contains(where: { "/\\?#@".contains($0) }),
              !host.unicodeScalars.contains(where: {
                  CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0)
              }) else {
            return "redacted"
        }
        let authorityHost = host.contains(":") ? "[\(host)]" : host
        let scheme: String
        switch protocolKind {
        case .shadowsocks: scheme = "ss"
        default: scheme = protocolKind.rawValue
        }
        return "\(scheme)://\(authorityHost):\(port)/••••••••"
    }
}
