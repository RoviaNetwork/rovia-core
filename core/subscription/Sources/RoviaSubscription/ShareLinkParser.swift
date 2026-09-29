import Foundation
import RoviaConfig

public typealias ShareLinkCredentialSink = (Data) throws -> SecretReference

public struct ShareLinkLimits: Equatable, Sendable {
    public static let maximumBytes = 1_048_576

    public let maximumBytes: Int

    public init(maximumBytes: Int = ShareLinkLimits.maximumBytes) {
        self.maximumBytes = Swift.min(Swift.max(0, maximumBytes), Self.maximumBytes)
    }
}

public enum ShareLinkParseError: Error, Equatable, Sendable {
    case inputTooLarge
    case invalidUTF8
    case emptyInput
    case malformedURL
    case unsupportedScheme
    case invalidCredential
    case invalidUUID
    case invalidHost
    case invalidPort
    case invalidPath
    case invalidPercentEncoding
    case invalidQuery
    case queryTooComplex
    case duplicateQueryKey
    case unsupportedQueryKey
    case unsupportedQueryValue
    case invalidSecretReference
    case credentialSinkFailed
}

enum CanonicalParsedShareLinkRules {
    private static let transportKinds: Set<String> = ["tcp", "ws", "grpc", "http", "httpupgrade"]
    private static let methods: Set<String> = [
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"
    ]
    private static let flows: Set<String> = ["xtls-rprx-vision", "xtls-rprx-vision-udp443"]
    private static let fingerprints: Set<String> = [
        "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"
    ]

    static func isSafe(server: Server, displayValue: String) -> Bool {
        let expectedName: String
        let scheme: String
        switch server.protocolKind {
        case .vless:
            expectedName = "VLESS server"
            scheme = "vless"
        case .trojan:
            expectedName = "Trojan server"
            scheme = "trojan"
        case .shadowsocks:
            expectedName = "Shadowsocks server"
            scheme = "ss"
        case .vmess:
            return false
        }
        let expectedDisplay = SubscriptionRedactor.redactShareLink(
            protocolKind: server.protocolKind,
            host: server.endpoint.host,
            port: server.endpoint.port
        )
        guard server.name == expectedName,
              server.tags == ["share-link", server.protocolKind.rawValue],
              displayValue == expectedDisplay,
              displayValue != "redacted",
              displayValue.utf8.count <= 512,
              (1...65_535).contains(server.endpoint.port),
              let normalizedHost = try? ShareLinkParser.validatedHost(server.endpoint.host),
              normalizedHost == server.endpoint.host,
              let reference = server.credential,
              SecretReference.isValidKey(reference.key),
              isSafeTransport(
                  protocolKind: server.protocolKind,
                  transport: server.transport,
                  tls: server.tls
              ) else {
            return false
        }
        return displayValue.hasPrefix("\(scheme)://")
    }

    static func isPrintableASCII(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { (33...126).contains($0) }
    }

    private static func isSafeTransport(
        protocolKind: ProxyProtocol,
        transport: TransportOptions,
        tls: TLSOptions?
    ) -> Bool {
        guard transportKinds.contains(transport.kind), transport.options.count <= 10 else {
            return false
        }
        let commonKeys: Set<String> = ["flow", "fingerprint"]
        var allowedKeys: Set<String>
        switch transport.kind {
        case "tcp":
            allowedKeys = Set(["host", "headerType", "realityPublicKey", "realityShortID"]).union(commonKeys)
        case "ws", "http", "httpupgrade":
            allowedKeys = Set(["host", "path"]).union(commonKeys)
        case "grpc":
            allowedKeys = Set(["serviceName", "mode"]).union(commonKeys)
        default:
            return false
        }
        if protocolKind == .shadowsocks {
            allowedKeys.insert("method")
        }
        guard transport.options.allSatisfy({ key, value in
            key.utf8.count <= 64 && isPrintableASCII(key) && value.utf8.count <= 2_048 && isPrintableASCII(value)
        }) else {
            return false
        }
        guard transport.options.keys.allSatisfy({ allowedKeys.contains($0) }), isSafeTLS(tls) else {
            return false
        }
        if let host = transport.options["host"] {
            guard host == host.lowercased(), let normalized = try? ShareLinkParser.validatedHost(host), normalized == host else {
                return false
            }
        }
        if let path = transport.options["path"],
           (try? ShareLinkParser.validatedPath(path)) != path {
            return false
        }
        if let serviceName = transport.options["serviceName"],
           !(1...128).contains(serviceName.utf8.count) || !isServiceName(serviceName) {
            return false
        }
        if let flow = transport.options["flow"], !flows.contains(flow) {
            return false
        }
        if let fingerprint = transport.options["fingerprint"], !fingerprints.contains(fingerprint) {
            return false
        }
        if let headerType = transport.options["headerType"],
           transport.kind != "tcp" || headerType != "http" {
            return false
        }
        if let mode = transport.options["mode"],
           transport.kind != "grpc" || !["gun", "multi"].contains(mode) {
            return false
        }
        if let method = transport.options["method"], !methods.contains(method) {
            return false
        }
        if let publicKey = transport.options["realityPublicKey"],
           !ShareLinkParser.isRealityPublicKey(publicKey) {
            return false
        }
        if let shortID = transport.options["realityShortID"],
           !ShareLinkParser.isRealityShortID(shortID) {
            return false
        }

        let hasFlow = transport.options["flow"] != nil
        let hasPublicKey = transport.options["realityPublicKey"] != nil
        let hasShortID = transport.options["realityShortID"] != nil
        let hasReality = hasPublicKey || hasShortID
        if hasFlow, tls == nil {
            return false
        }
        if hasReality, (tls == nil || transport.kind != "tcp" || !hasPublicKey) {
            return false
        }

        switch protocolKind {
        case .vless:
            return tls != nil && transport.options["method"] == nil
        case .trojan:
            return tls != nil && !hasReality && transport.options["method"] == nil
        case .shadowsocks:
            return transport.kind == "tcp" &&
                transport.options.count == 1 &&
                methods.contains(transport.options["method"] ?? "") &&
                tls == nil
        case .vmess:
            return false
        }
    }

    static func isServiceName(_ value: String) -> Bool {
        value.utf8.allSatisfy { byte in
            (48...57).contains(byte) ||
            (65...90).contains(byte) ||
            (97...122).contains(byte) ||
            byte == 45 || byte == 46 || byte == 95
        }
    }

    private static func isSafeTLS(_ tls: TLSOptions?) -> Bool {
        guard let tls else { return true }
        guard let serverName = tls.serverName,
              serverName == serverName.lowercased(),
              let normalized = try? ShareLinkParser.validatedHost(serverName),
              normalized == serverName,
              tls.alpn.count <= 32,
              Set(tls.alpn).count == tls.alpn.count else {
            return false
        }
        return tls.alpn.allSatisfy { value in
            (1...64).contains(value.utf8.count) && isPrintableASCII(value)
        }
    }
}

public struct ParsedShareLink: Codable, Equatable, Sendable {
    public let server: Server
    public let displayValue: String

    public var secretReference: SecretReference {
        guard let reference = server.credential else {
            preconditionFailure("Parsed share links require a secret reference")
        }
        return reference
    }

    init(server: Server, displayValue: String) {
        self.server = server
        self.displayValue = displayValue
    }

    public init(from decoder: Decoder) throws {
        let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)
        let allowedKeys: Set<String> = ["server", "displayValue"]
        guard dynamicContainer.allKeys.allSatisfy({ allowedKeys.contains($0.stringValue) }),
              dynamicContainer.allKeys.count == allowedKeys.count else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid parsed share-link fields"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let server = try container.decode(Server.self, forKey: .server)
        let displayValue = try container.decode(String.self, forKey: .displayValue)
        guard Self.isSafe(server: server, displayValue: displayValue) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid parsed share-link metadata"
                )
            )
        }
        self.init(server: server, displayValue: displayValue)
    }

    public func encode(to encoder: Encoder) throws {
        guard Self.isSafe(server: server, displayValue: displayValue) else {
            throw EncodingError.invalidValue(
                "redacted",
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Invalid parsed share-link metadata"
                )
            )
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(server, forKey: .server)
        try container.encode(displayValue, forKey: .displayValue)
    }

    private enum CodingKeys: String, CodingKey {
        case server
        case displayValue
    }

    private struct DynamicCodingKey: CodingKey {
        let stringValue: String
        let intValue: Int?

        init?(stringValue: String) {
            self.stringValue = stringValue
            intValue = nil
        }

        init?(intValue: Int) {
            stringValue = String(intValue)
            self.intValue = intValue
        }
    }

    private static func isSafe(server: Server, displayValue: String) -> Bool {
        CanonicalParsedShareLinkRules.isSafe(server: server, displayValue: displayValue)
    }
}

public enum ShareLinkParser {
    private static let maximumUserInfoBytes = 4_096
    private static let maximumQueryBytes = 4_096
    private static let maximumFragmentBytes = 1_024
    private static let maximumQueryItems = 32

    private enum Scheme: Equatable {
        case vless
        case trojan
        case shadowsocks

        var protocolKind: ProxyProtocol {
            switch self {
            case .vless: .vless
            case .trojan: .trojan
            case .shadowsocks: .shadowsocks
            }
        }

        var serverName: String {
            switch self {
            case .vless: "VLESS server"
            case .trojan: "Trojan server"
            case .shadowsocks: "Shadowsocks server"
            }
        }

        var allowedQueryKeys: Set<String> {
            switch self {
            case .vless:
                return [
                    "encryption", "security", "sni", "alpn", "type", "host", "path", "serviceName",
                    "flow", "fp", "headerType", "allowInsecure", "mode", "pbk", "sid"
                ]
            case .trojan:
                return [
                    "security", "peer", "sni", "alpn", "type", "host", "path", "serviceName",
                    "flow", "fp", "headerType", "allowInsecure", "mode"
                ]
            case .shadowsocks:
                return ["plugin"]
            }
        }
    }

    private struct LinkStructure {
        let scheme: Scheme
        let rawUserInfo: String
        let host: String
        let port: Int
        let rawQuery: String?
    }

    private struct Candidate {
        let host: String
        let port: Int
        var secret: Data
        let transport: TransportOptions
        let tls: TLSOptions?
    }

    public static func parse(
        _ data: Data,
        id: UUID,
        credentialSink: ShareLinkCredentialSink,
        limits: ShareLinkLimits = ShareLinkLimits()
    ) throws -> ParsedShareLink {
        guard data.count <= limits.maximumBytes else {
            throw ShareLinkParseError.inputTooLarge
        }
        guard var text = String(data: data, encoding: .utf8) else {
            throw ShareLinkParseError.invalidUTF8
        }
        removeTrailingLineEnding(from: &text)
        guard !text.isEmpty else {
            throw ShareLinkParseError.emptyInput
        }
        try validateRawURL(text)

        let structure = try parseStructure(text)
        let query = try parseQuery(structure.rawQuery, allowedKeys: structure.scheme.allowedQueryKeys)
        var candidate = try parseCandidate(structure, query: query)
        let secretReference = try store(&candidate.secret, using: credentialSink)
        let server = Server(
            id: id,
            name: structure.scheme.serverName,
            protocolKind: structure.scheme.protocolKind,
            endpoint: Endpoint(host: candidate.host, port: candidate.port),
            credential: secretReference,
            transport: candidate.transport,
            tls: candidate.tls,
            tags: ["share-link", structure.scheme.protocolKind.rawValue]
        )
        return ParsedShareLink(
            server: server,
            displayValue: SubscriptionRedactor.redactShareLink(
                protocolKind: structure.scheme.protocolKind,
                host: candidate.host,
                port: candidate.port
            )
        )
    }

    private static func removeTrailingLineEnding(from text: inout String) {
        if text.hasSuffix("\r\n") {
            text.removeLast(2)
        } else if text.hasSuffix("\n") || text.hasSuffix("\r") {
            text.removeLast()
        }
    }

    private static func validateRawURL(_ text: String) throws {
        guard !text.unicodeScalars.contains(where: { scalar in
            CharacterSet.whitespacesAndNewlines.contains(scalar) || CharacterSet.controlCharacters.contains(scalar)
        }) else {
            throw ShareLinkParseError.malformedURL
        }
        guard !text.contains("\\") else {
            throw ShareLinkParseError.malformedURL
        }
        guard text.unicodeScalars.allSatisfy({ !isControlScalar($0) }) else {
            throw ShareLinkParseError.malformedURL
        }
        try validatePercentEncoding(text)
        guard text.count(where: { $0 == "?" }) <= 1, text.count(where: { $0 == "#" }) <= 1 else {
            throw ShareLinkParseError.malformedURL
        }
    }

    private static func parseStructure(_ text: String) throws -> LinkStructure {
        guard let schemeRange = text.range(of: "://") else {
            throw ShareLinkParseError.malformedURL
        }
        let rawScheme = String(text[..<schemeRange.lowerBound])
        let scheme = try parseScheme(rawScheme)
        let authorityStart = schemeRange.upperBound
        let remainder = text[authorityStart...]
        let authorityEnd = remainder.firstIndex(where: { character in
            character == "/" || character == "?" || character == "#"
        }) ?? remainder.endIndex
        let authority = String(remainder[..<authorityEnd])
        let rawTail = String(remainder[authorityEnd...])
        let userInfoAndHost = try splitAuthority(authority)
        let host = try validatedHost(userInfoAndHost.host)
        let port = try validatedPort(userInfoAndHost.port)
        let components = try splitTail(rawTail)

        guard userInfoAndHost.userInfo.utf8.count <= maximumUserInfoBytes, !userInfoAndHost.userInfo.isEmpty else {
            throw ShareLinkParseError.invalidCredential
        }
        try validateRawUserInfo(userInfoAndHost.userInfo)
        if components.path.utf8.count > 1, components.path != "/" {
            throw ShareLinkParseError.invalidPath
        }
        if components.path == "/" {
            _ = try percentDecodedString(components.path)
        }
        if let fragment = components.fragment {
            guard fragment.utf8.count <= maximumFragmentBytes else {
                throw ShareLinkParseError.malformedURL
            }
            let decodedFragment = try percentDecodedString(fragment)
            guard !decodedFragment.unicodeScalars.contains(where: { isControlScalar($0) }) else {
                throw ShareLinkParseError.malformedURL
            }
        }
        return LinkStructure(
            scheme: scheme,
            rawUserInfo: userInfoAndHost.userInfo,
            host: host,
            port: port,
            rawQuery: components.query
        )
    }

    private static func parseScheme(_ rawScheme: String) throws -> Scheme {
        guard !rawScheme.isEmpty,
              rawScheme.utf8.count <= 32,
              rawScheme.utf8.allSatisfy({ character in
                  (Character("a")..."z").contains(Character(UnicodeScalar(character))) ||
                  (Character("A")..."Z").contains(Character(UnicodeScalar(character)))
              }) else {
            throw ShareLinkParseError.malformedURL
        }
        switch rawScheme.lowercased() {
        case "vless": return .vless
        case "trojan": return .trojan
        case "ss": return .shadowsocks
        case "vmess", "ssr", "http", "https": throw ShareLinkParseError.unsupportedScheme
        default: throw ShareLinkParseError.unsupportedScheme
        }
    }

    private static func splitAuthority(_ authority: String) throws -> (userInfo: String, host: String, port: String) {
        guard !authority.isEmpty, authority.count(where: { $0 == "@" }) <= 1 else {
            throw ShareLinkParseError.malformedURL
        }
        let pieces = authority.split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false)
        guard pieces.count == 2, !pieces[0].isEmpty else {
            throw ShareLinkParseError.invalidCredential
        }
        let userInfo = String(pieces[0])
        let hostAndPort = String(pieces[1])
        if hostAndPort.hasPrefix("[") {
            guard let closingBracket = hostAndPort.firstIndex(of: "]") else {
                throw ShareLinkParseError.invalidHost
            }
            let host = String(hostAndPort[hostAndPort.index(after: hostAndPort.startIndex)..<closingBracket])
            guard host.contains(":"), isValidIPv6(host) else {
                throw ShareLinkParseError.invalidHost
            }
            let remainder = hostAndPort[hostAndPort.index(after: closingBracket)...]
            guard remainder.hasPrefix(":"), remainder.count > 1 else {
                throw ShareLinkParseError.invalidPort
            }
            return (userInfo, host, String(remainder.dropFirst()))
        }
        let piecesByPort = hostAndPort.split(separator: ":", omittingEmptySubsequences: false)
        guard piecesByPort.count == 2, !piecesByPort[0].isEmpty, !piecesByPort[1].isEmpty else {
            if piecesByPort.count > 1 {
                throw ShareLinkParseError.invalidHost
            }
            throw ShareLinkParseError.invalidPort
        }
        return (userInfo, String(piecesByPort[0]), String(piecesByPort[1]))
    }

    private static func splitTail(_ tail: String) throws -> (path: String, query: String?, fragment: String?) {
        let queryIndex = tail.firstIndex(of: "?")
        let fragmentIndex = tail.firstIndex(of: "#")
        if let queryIndex, let fragmentIndex, fragmentIndex < queryIndex {
            throw ShareLinkParseError.malformedURL
        }

        let pathEnd = queryIndex ?? fragmentIndex ?? tail.endIndex
        let path = String(tail[..<pathEnd])
        var query: String?
        var fragment: String?
        if let queryIndex {
            let queryStart = tail.index(after: queryIndex)
            let queryEnd = fragmentIndex ?? tail.endIndex
            query = String(tail[queryStart..<queryEnd])
        }
        if let fragmentIndex {
            fragment = String(tail[tail.index(after: fragmentIndex)...])
        }
        return (path, query, fragment)
    }

    private static func validatedPort(_ rawPort: String) throws -> Int {
        guard !rawPort.isEmpty,
              rawPort.utf8.count <= 5,
              rawPort.utf8.allSatisfy({ (48...57).contains($0) }),
              rawPort.count == 1 || rawPort.first != "0",
              let port = Int(rawPort),
              (1...65_535).contains(port) else {
            throw ShareLinkParseError.invalidPort
        }
        return port
    }

    static func validatedHost(_ rawHost: String) throws -> String {
        guard !rawHost.isEmpty, !rawHost.contains("%") else {
            throw ShareLinkParseError.invalidHost
        }
        let host = rawHost.lowercased()
        if host.contains(":") {
            guard isValidIPv6(host) else {
                throw ShareLinkParseError.invalidHost
            }
            return host
        }
        if isValidIPv4(host) {
            return host
        }
        guard !host.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) else {
            throw ShareLinkParseError.invalidHost
        }
        let normalized = host.hasSuffix(".") ? String(host.dropLast()) : host
        guard normalized.utf8.count <= 253 else {
            throw ShareLinkParseError.invalidHost
        }
        let labels = normalized.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty,
              labels.allSatisfy({ label in
                  !label.isEmpty &&
                  label.utf8.count <= 63 &&
                  label.utf8.allSatisfy({ byte in
                      (48...57).contains(byte) ||
                      (65...90).contains(byte) ||
                      (97...122).contains(byte) ||
                      byte == 45
                  }) &&
                  isASCIIAlphanumeric(label.first!) &&
                  isASCIIAlphanumeric(label.last!)
              }) else {
            throw ShareLinkParseError.invalidHost
        }
        return normalized
    }

    private static func isValidIPv4(_ host: String) -> Bool {
        let components = host.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4 else { return false }
        return components.allSatisfy { component in
            guard !component.isEmpty,
                  component.utf8.count <= 3,
                  component.utf8.allSatisfy({ (48...57).contains($0) }) else {
                return false
            }
            guard component.count == 1 || component.first != "0" else { return false }
            return Int(component).map { (0...255).contains($0) } ?? false
        }
    }

    private static func isValidIPv6(_ host: String) -> Bool {
        let sections = host.components(separatedBy: "::")
        guard sections.count <= 2 else { return false }
        func normalizedGroups(_ section: String) -> [String]? {
            if section.isEmpty { return [] }
            var components = section.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            if let last = components.last, last.contains(".") {
                guard isValidIPv4(last) else { return nil }
                let octets = last.split(separator: ".").compactMap { Int($0) }
                components.removeLast()
                components.append(String(format: "%x", (octets[0] << 8) | octets[1]))
                components.append(String(format: "%x", (octets[2] << 8) | octets[3]))
            }
            guard components.allSatisfy({ group in
                (1...4).contains(group.utf8.count) && group.utf8.allSatisfy(isHexDigit)
            }) else {
                return nil
            }
            return components
        }
        guard let left = normalizedGroups(sections[0]) else { return false }
        guard sections.count == 2 else { return left.count == 8 }
        guard let right = normalizedGroups(sections[1]) else { return false }
        return left.count + right.count <= 7
    }

    private static func validateRawUserInfo(_ value: String) throws {
        let bytes = Array(value.utf8)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 37 {
                index += 3
            } else {
                guard isRawUserInfoByte(bytes[index]) else {
                    throw ShareLinkParseError.invalidCredential
                }
                index += 1
            }
        }
    }

    private static func isRawUserInfoByte(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) ||
        (65...90).contains(byte) ||
        (97...122).contains(byte) ||
        byte == 45 || byte == 46 || byte == 95 || byte == 126 ||
        byte == 33 || byte == 36 || byte == 38 || byte == 39 ||
        byte == 40 || byte == 41 || byte == 42 || byte == 43 ||
        byte == 44 || byte == 59 || byte == 61 || byte == 58
    }

    private static func validatePercentEncoding(_ value: String) throws {
        let bytes = Array(value.utf8)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 37 {
                guard index + 2 < bytes.count,
                      isHexDigit(bytes[index + 1]),
                      isHexDigit(bytes[index + 2]) else {
                    throw ShareLinkParseError.invalidPercentEncoding
                }
                index += 3
            } else {
                index += 1
            }
        }
    }

    private static func percentDecodedData(_ value: String) throws -> Data {
        let bytes = Array(value.utf8)
        var decoded = Data()
        decoded.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 37 {
                guard index + 2 < bytes.count,
                      let high = hexValue(bytes[index + 1]),
                      let low = hexValue(bytes[index + 2]) else {
                    throw ShareLinkParseError.invalidPercentEncoding
                }
                decoded.append((high << 4) | low)
                index += 3
            } else {
                decoded.append(bytes[index])
                index += 1
            }
        }
        return decoded
    }

    private static func percentDecodedString(_ value: String) throws -> String {
        let data = try percentDecodedData(value)
        guard let decoded = String(data: data, encoding: .utf8) else {
            throw ShareLinkParseError.invalidPercentEncoding
        }
        return decoded
    }

    private static func parseQuery(_ rawQuery: String?, allowedKeys: Set<String>) throws -> [String: String] {
        guard let rawQuery else { return [:] }
        guard !rawQuery.isEmpty, rawQuery.utf8.count <= maximumQueryBytes else {
            throw ShareLinkParseError.invalidQuery
        }
        let components = rawQuery.split(separator: "&", omittingEmptySubsequences: false)
        guard !components.isEmpty, components.count <= maximumQueryItems else {
            throw ShareLinkParseError.queryTooComplex
        }
        var values: [String: String] = [:]
        for component in components {
            guard !component.isEmpty, component.utf8.count <= maximumQueryBytes else {
                throw ShareLinkParseError.invalidQuery
            }
            // Split on the first `=` only: values are percent-encoded, so a
            // raw `=` after the first one belongs to the value and is judged
            // by per-key validation, not here. Empty values are allowed
            // through (`sid=` is legal); each key decides whether empty is
            // acceptable. A missing `=` or an empty key is still malformed.
            guard let equals = component.firstIndex(of: "=") else {
                throw ShareLinkParseError.invalidQuery
            }
            let rawKey = String(component[..<equals])
            let rawValue = String(component[component.index(after: equals)...])
            guard !rawKey.isEmpty else {
                throw ShareLinkParseError.invalidQuery
            }
            let key = try percentDecodedString(rawKey)
            let value = try percentDecodedString(rawValue)
            guard key.utf8.allSatisfy({ byte in
                (48...57).contains(byte) ||
                (65...90).contains(byte) ||
                (97...122).contains(byte)
            }) else {
                throw ShareLinkParseError.invalidQuery
            }
            guard values.updateValue(value, forKey: key) == nil else {
                throw ShareLinkParseError.duplicateQueryKey
            }
            guard allowedKeys.contains(key) else {
                guard allowedKeys.contains(where: { $0.lowercased() == key.lowercased() }) else {
                    throw ShareLinkParseError.unsupportedQueryKey
                }
                throw ShareLinkParseError.invalidQuery
            }
            guard !value.unicodeScalars.contains(where: { isControlScalar($0) }) else {
                throw ShareLinkParseError.invalidQuery
            }
        }
        return values
    }

    private static func parseCandidate(_ structure: LinkStructure, query: [String: String]) throws -> Candidate {
        switch structure.scheme {
        case .vless:
            return try parseVLESS(structure, query: query)
        case .trojan:
            return try parseTrojan(structure, query: query)
        case .shadowsocks:
            return try parseShadowsocks(structure, query: query)
        }
    }

    private static func parseVLESS(_ structure: LinkStructure, query: [String: String]) throws -> Candidate {
        // The canonical shape is the only rule: a lowercased UUID. The old
        // pre-check (`allSatisfy(isHexDigit) || allSatisfy(45...57)`) rejected
        // every UUID containing a–f, because dashes are not hex digits and
        // letters are not in 45...57 — so only all-digit UUIDs passed.
        let normalizedUUID = structure.rawUserInfo.lowercased()
        guard isCanonicalUUID(normalizedUUID),
              normalizedUUID != "00000000-0000-0000-0000-000000000000" else {
            throw ShareLinkParseError.invalidUUID
        }
        guard let encryption = query["encryption"] else {
            throw ShareLinkParseError.unsupportedQueryValue
        }
        guard encryption == "none" else {
            throw ShareLinkParseError.unsupportedQueryValue
        }
        let common = try parseCommonQuery(query, scheme: .vless, endpointHost: structure.host)
        return Candidate(
            host: structure.host,
            port: structure.port,
            secret: Data(normalizedUUID.utf8),
            transport: common.transport,
            tls: common.tls
        )
    }

    private static func parseTrojan(_ structure: LinkStructure, query: [String: String]) throws -> Candidate {
        if let sni = query["sni"], let peer = query["peer"], sni != peer {
            throw ShareLinkParseError.invalidQuery
        }
        let password = try percentDecodedString(structure.rawUserInfo)
        guard !password.isEmpty,
              password.utf8.count <= maximumUserInfoBytes,
              !password.unicodeScalars.contains(where: { isControlScalar($0) }) else {
            throw ShareLinkParseError.invalidCredential
        }
        let common = try parseCommonQuery(query, scheme: .trojan, endpointHost: structure.host)
        return Candidate(
            host: structure.host,
            port: structure.port,
            secret: Data(password.utf8),
            transport: common.transport,
            tls: common.tls
        )
    }

    private static func parseShadowsocks(_ structure: LinkStructure, query: [String: String]) throws -> Candidate {
        guard query.isEmpty else {
            throw ShareLinkParseError.unsupportedQueryValue
        }
        let credential: (method: String, password: String)
        if structure.rawUserInfo.contains(":") || structure.rawUserInfo.contains("%") {
            credential = try parsePlainSIP002UserInfo(structure.rawUserInfo)
        } else {
            credential = try parseBase64SIP002UserInfo(structure.rawUserInfo)
        }
        return Candidate(
            host: structure.host,
            port: structure.port,
            secret: Data(credential.password.utf8),
            transport: TransportOptions(kind: "tcp", options: ["method": credential.method]),
            tls: nil
        )
    }

    private static func parsePlainSIP002UserInfo(_ rawUserInfo: String) throws -> (method: String, password: String) {
        let components = rawUserInfo.split(separator: ":", omittingEmptySubsequences: false)
        guard components.count == 2 else {
            throw ShareLinkParseError.invalidCredential
        }
        try validatePercentEncodedPlainComponent(String(components[0]))
        try validatePercentEncodedPlainComponent(String(components[1]))
        let method = try percentDecodedString(String(components[0])).lowercased()
        let password = try percentDecodedString(String(components[1]))
        return try validatedShadowsocksCredential(method: method, password: password)
    }

    private static func validatePercentEncodedPlainComponent(_ value: String) throws {
        let bytes = Array(value.utf8)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 37 {
                guard index + 2 < bytes.count,
                      isHexDigit(bytes[index + 1]),
                      isHexDigit(bytes[index + 2]),
                      let high = hexValue(bytes[index + 1]),
                      let low = hexValue(bytes[index + 2]) else {
                    throw ShareLinkParseError.invalidPercentEncoding
                }
                let decoded = (high << 4) | low
                guard !isUnreservedByte(decoded) else {
                    throw ShareLinkParseError.invalidCredential
                }
                index += 3
            } else {
                guard isUnreservedByte(bytes[index]) else {
                    throw ShareLinkParseError.invalidCredential
                }
                index += 1
            }
        }
    }

    private static func parseBase64SIP002UserInfo(_ rawUserInfo: String) throws -> (method: String, password: String) {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        guard !rawUserInfo.isEmpty,
              rawUserInfo.utf8.count <= maximumUserInfoBytes,
              rawUserInfo.unicodeScalars.allSatisfy({ alphabet.unicodeScalars.contains($0) }),
              hasCanonicalBase64PadBits(rawUserInfo, alphabet: Array(alphabet)) else {
            throw ShareLinkParseError.invalidCredential
        }
        let normalizedBase64 = rawUserInfo.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padded = normalizedBase64 + String(repeating: "=", count: (4 - normalizedBase64.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded),
              let userInfo = String(data: decoded, encoding: .utf8),
              let separator = userInfo.firstIndex(of: ":") else {
            throw ShareLinkParseError.invalidCredential
        }
        return try validatedShadowsocksCredential(
            method: String(userInfo[..<separator]).lowercased(),
            password: String(userInfo[userInfo.index(after: separator)...])
        )
    }

    private static func hasCanonicalBase64PadBits(_ value: String, alphabet: [Character]) -> Bool {
        guard let last = value.last,
              let lastIndex = alphabet.firstIndex(of: last) else {
            return false
        }
        switch value.utf8.count % 4 {
        case 0: return true
        case 1: return false
        case 2: return lastIndex.isMultiple(of: 16)
        case 3: return lastIndex.isMultiple(of: 4)
        default: return false
        }
    }

    private static func validatedShadowsocksCredential(
        method: String,
        password: String
    ) throws -> (method: String, password: String) {
        let supportedMethods: Set<String> = [
            "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"
        ]
        guard supportedMethods.contains(method),
              !password.isEmpty,
              password.utf8.count <= maximumUserInfoBytes,
              !password.unicodeScalars.contains(where: { isControlScalar($0) }) else {
            throw ShareLinkParseError.invalidCredential
        }
        return (method, password)
    }

    private static func isUnreservedByte(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) ||
        (65...90).contains(byte) ||
        (97...122).contains(byte) ||
        byte == 45 || byte == 46 || byte == 95 || byte == 126
    }

    private static func parseCommonQuery(
        _ query: [String: String],
        scheme: Scheme,
        endpointHost: String
    ) throws -> (transport: TransportOptions, tls: TLSOptions?) {
        let security = try enumValue(
            query["security"] ?? (scheme == .trojan ? "tls" : "none"),
            key: "security",
            allowed: ["none", "tls", "reality"]
        )
        if scheme == .trojan || scheme == .vless, security == "none" {
            throw ShareLinkParseError.unsupportedQueryValue
        }
        let transportType = try enumValue(
            query["type"] ?? "tcp",
            key: "type",
            allowed: ["tcp", "ws", "grpc", "http", "httpupgrade"]
        )
        if security == "reality", transportType != "tcp" {
            throw ShareLinkParseError.unsupportedQueryValue
        }
        var options: [String: String] = [:]
        try validateTransportQueryKeys(transportType, query: query)
        if let host = query["host"] {
            options["host"] = try validatedHost(host)
        }
        if let path = query["path"] {
            options["path"] = try validatedPath(path)
        }
        if let serviceName = query["serviceName"] {
            guard serviceName.utf8.count <= 128,
                  CanonicalParsedShareLinkRules.isServiceName(serviceName) else {
                throw ShareLinkParseError.invalidQuery
            }
            options["serviceName"] = serviceName
        }
        if let flow = query["flow"] {
            guard ["xtls-rprx-vision", "xtls-rprx-vision-udp443"].contains(flow), security != "none" else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
            options["flow"] = flow
        }
        if let fingerprint = query["fp"] {
            let allowedFingerprints: Set<String> = [
                "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"
            ]
            guard security != "none", allowedFingerprints.contains(fingerprint) else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
            options["fingerprint"] = fingerprint
        }
        if let headerType = query["headerType"] {
            guard transportType == "tcp", ["none", "http"].contains(headerType) else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
            if headerType == "http" {
                options["headerType"] = headerType
            }
        }
        if let mode = query["mode"] {
            guard transportType == "grpc", ["gun", "multi"].contains(mode) else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
            options["mode"] = mode
        }
        if let publicKey = query["pbk"] {
            guard security == "reality", isRealityPublicKey(publicKey) else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
            options["realityPublicKey"] = publicKey
        }
        if let shortID = query["sid"] {
            guard security == "reality", isRealityShortID(shortID) else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
            if !shortID.isEmpty {
                options["realityShortID"] = shortID
            }
        }
        if security == "reality", query["pbk"] == nil {
            throw ShareLinkParseError.unsupportedQueryValue
        }

        let tls: TLSOptions?
        if security == "none" {
            guard query["sni"] == nil,
                  query["peer"] == nil,
                  query["alpn"] == nil,
                  query["fp"] == nil,
                  query["allowInsecure"] == nil else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
            tls = nil
        } else {
            let serverNameValue = query["sni"] ?? query["peer"] ?? endpointHost
            let serverName = try validatedHost(serverNameValue)
            let allowInsecure = try booleanValue(query["allowInsecure"])
            let alpn = try alpnValues(query["alpn"])
            tls = TLSOptions(serverName: serverName, allowInsecure: allowInsecure, alpn: alpn)
        }
        return (TransportOptions(kind: transportType, options: options), tls)
    }

    private static func validateTransportQueryKeys(_ transportType: String, query: [String: String]) throws {
        if transportType == "tcp" {
            guard query["path"] == nil, query["serviceName"] == nil, query["mode"] == nil else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
        } else if transportType == "ws" || transportType == "http" || transportType == "httpupgrade" {
            guard query["serviceName"] == nil,
                  query["mode"] == nil,
                  query["headerType"] == nil else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
        } else if transportType == "grpc" {
            guard query["host"] == nil,
                  query["path"] == nil,
                  query["headerType"] == nil else {
                throw ShareLinkParseError.unsupportedQueryValue
            }
        }
        if transportType != "tcp", query["headerType"] != nil {
            throw ShareLinkParseError.unsupportedQueryValue
        }
    }

    static func validatedPath(_ path: String) throws -> String {
        guard path.hasPrefix("/"),
              path.utf8.count <= 2_048,
              CanonicalParsedShareLinkRules.isPrintableASCII(path),
              !path.contains("?"),
              !path.contains("#"),
              !path.unicodeScalars.contains(where: {
                  isControlScalar($0) || CharacterSet.whitespacesAndNewlines.contains($0)
              }) else {
            throw ShareLinkParseError.invalidPath
        }
        return path
    }

    private static func enumValue(_ value: String, key: String, allowed: Set<String>) throws -> String {
        guard allowed.contains(value) else {
            throw ShareLinkParseError.unsupportedQueryValue
        }
        return value
    }

    private static func booleanValue(_ value: String?) throws -> Bool {
        guard let value else { return false }
        switch value {
        case "0": return false
        case "1": return true
        default: throw ShareLinkParseError.unsupportedQueryValue
        }
    }

    private static func alpnValues(_ value: String?) throws -> [String] {
        guard let value else { return [] }
        let entries = value.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard !entries.isEmpty,
              entries.count <= 32,
              entries.allSatisfy({ entry in
                  (1...64).contains(entry.utf8.count) &&
                  CanonicalParsedShareLinkRules.isPrintableASCII(entry)
              }),
              Set(entries).count == entries.count else {
            throw ShareLinkParseError.unsupportedQueryValue
        }
        return entries
    }

    static func isRealityPublicKey(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy { byte in
            (45...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte) || byte == 95
        }
    }

    static func isRealityShortID(_ value: String) -> Bool {
        value.utf8.count <= 16 && value.utf8.count.isMultiple(of: 2) && value.utf8.allSatisfy(isHexDigit)
    }

    private static func isCanonicalUUID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 36 else { return false }
        for index in bytes.indices where [8, 13, 18, 23].contains(index) {
            guard bytes[index] == 45 else { return false }
        }
        let hexIndices = bytes.indices.filter { ![8, 13, 18, 23].contains($0) }
        return hexIndices.allSatisfy { isHexDigit(bytes[$0]) }
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (65...70).contains(byte) || (97...102).contains(byte)
    }

    private static func isControlScalar(_ scalar: Unicode.Scalar) -> Bool {
        CharacterSet.controlCharacters.contains(scalar)
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48...57: byte - 48
        case 65...70: byte - 55
        case 97...102: byte - 87
        default: nil
        }
    }

    private static func isASCIIAlphanumeric(_ character: Character) -> Bool {
        character.isASCII && (character.isLetter || character.isNumber)
    }

    private static func store(_ secret: inout Data, using sink: ShareLinkCredentialSink) throws -> SecretReference {
        defer {
            _ = secret.withUnsafeMutableBytes { bytes in
                bytes.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }
        let reference: SecretReference
        do {
            reference = try sink(secret)
        } catch {
            throw ShareLinkParseError.credentialSinkFailed
        }
        if let secretText = String(data: secret, encoding: .utf8),
           reference.key.contains(secretText) {
            throw ShareLinkParseError.invalidSecretReference
        }
        // One rule, stated once: RoviaConfig owns what a secret reference key
        // may be, and the parser asks it rather than keeping a second copy of
        // the limit and the character set.
        guard SecretReference.isValidKey(reference.key) else {
            throw ShareLinkParseError.invalidSecretReference
        }
        return reference
    }
}
