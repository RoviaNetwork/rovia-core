import Foundation

public enum CanonicalConfigError: Error, Equatable, Sendable {
    case invalidSchemaVersion(Int)
    case invalidServerPort(Int)
    case duplicateServerID(UUID)
    case unknownServerReference(UUID)
    case unknownGroupReference(UUID)
    case unsafeTransportOption(String)
    case unsafePrivacyPolicy
    case missingSchemaVersion
    case unknownField(path: String)
    case invalidField(path: String)
    case invalidJSON
}

public enum ProxyProtocol: String, Codable, Sendable, Equatable {
    case vless
    case vmess
    case trojan
    case shadowsocks
}

public enum GroupMode: String, Codable, Sendable, Equatable {
    case manual
    case lowestLatency
    case failover
}

public enum SelectionPolicy: String, Codable, Sendable, Equatable {
    case manual
    case lowestLatency
    case failover
}

public struct SecretReference: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable, Equatable {
        case keychain
    }

    /// The largest key a secret reference may carry, in UTF-8 bytes.
    ///
    /// A key names a secret; it is not the secret, and it is not a place to
    /// stash one. A bound keeps a key from becoming a covert channel for
    /// unbounded data, and matches the limit `RoviaSubscription` already
    /// enforces on the keys it mints.
    public static let maximumKeyBytes = 512

    public let kind: Kind
    public let key: String

    public init(kind: Kind = .keychain, key: String) {
        self.kind = kind
        self.key = key
    }

    /// Whether a key is usable: non-empty, at most `maximumKeyBytes` bytes, and
    /// printable ASCII only.
    ///
    /// The rule is stated once, here, and the JSON Schema states the same rule in
    /// `schemas/config.schema.json`. Printable ASCII without the space character
    /// (0x21–0x7E) is what a keychain account name and a configuration key can
    /// both carry unambiguously: a control character, a newline, or a non-ASCII
    /// digit has more than one visual form, which is exactly what a key that ends
    /// up in a path, a log line, or a diff must not have.
    public static func isValidKey(_ key: String) -> Bool {
        let bytes = key.utf8
        guard !bytes.isEmpty, bytes.count <= maximumKeyBytes else { return false }
        return bytes.allSatisfy { (0x21...0x7E).contains($0) }
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case key
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["kind", "key"],
            description: "Unknown secret reference field"
        )
        kind = try container.decode(Kind.self, forKey: .kind)
        key = try container.decode(String.self, forKey: .key)
        // The loader refuses as well as the validator, so a key that is not
        // usable cannot reach a caller that skipped validation.
        guard SecretReference.isValidKey(key) else {
            throw CanonicalConfigError.invalidField(path: "secretReference.key")
        }
    }
}

public struct Endpoint: Codable, Sendable, Equatable {
    public let host: String
    public let port: Int

    public init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    private enum CodingKeys: String, CodingKey {
        case host
        case port
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["host", "port"],
            description: "Unknown endpoint field"
        )
        host = try container.decode(String.self, forKey: .host)
        port = try container.decode(Int.self, forKey: .port)
    }
}

public struct TransportOptions: Codable, Sendable, Equatable {
    public let kind: String
    public let options: [String: String]

    public init(kind: String, options: [String: String] = [:]) {
        self.kind = kind
        self.options = options
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case options
    }

    public static func isSecretBearingKey(_ key: String) -> Bool {
        let normalized = key.lowercased().filter { $0.isLetter || $0.isNumber }
        let sensitiveFragments = [
            "password", "passwd", "passphrase", "pwd", "psk", "token", "secret", "uuid", "credential",
            "privatekey", "apikey", "accesskey", "authorization", "bearer", "cookie", "auth"
        ]
        return sensitiveFragments.contains(where: normalized.contains)
    }

    public static func secretBearingKey(in options: [String: String]) -> String? {
        options.keys.first(where: isSecretBearingKey)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["kind", "options"],
            description: "Unknown transport option field"
        )
        kind = try container.decode(String.self, forKey: .kind)
        options = try container.decode([String: String].self, forKey: .options)
        if decoder.userInfo[canonicalStructuralDecodingKey] as? Bool != true,
           Self.secretBearingKey(in: options) != nil {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Transport options cannot contain secret-bearing keys"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        if Self.secretBearingKey(in: options) != nil {
            throw EncodingError.invalidValue(
                "redacted",
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Transport options cannot contain secret-bearing keys"
                )
            )
        }

        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind, forKey: .kind)
        try container.encode(options, forKey: .options)
    }
}

public struct TLSOptions: Codable, Sendable, Equatable {
    public let serverName: String?
    public let allowInsecure: Bool
    public let alpn: [String]

    public init(serverName: String? = nil, allowInsecure: Bool = false, alpn: [String] = []) {
        self.serverName = serverName
        self.allowInsecure = allowInsecure
        self.alpn = alpn
    }

    private enum CodingKeys: String, CodingKey {
        case serverName
        case allowInsecure
        case alpn
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["serverName", "allowInsecure", "alpn"],
            description: "Unknown TLS options field"
        )
        serverName = try container.decodeIfPresent(String.self, forKey: .serverName)
        allowInsecure = try container.decode(Bool.self, forKey: .allowInsecure)
        alpn = try container.decode([String].self, forKey: .alpn)
    }
}

public struct Server: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public let name: String
    public let protocolKind: ProxyProtocol
    public let endpoint: Endpoint
    public let credential: SecretReference?
    public let transport: TransportOptions
    public let tls: TLSOptions?
    public let tags: [String]

    public init(
        id: UUID,
        name: String,
        protocolKind: ProxyProtocol,
        endpoint: Endpoint,
        credential: SecretReference? = nil,
        transport: TransportOptions,
        tls: TLSOptions? = nil,
        tags: [String] = []
    ) {
        self.id = id
        self.name = name
        self.protocolKind = protocolKind
        self.endpoint = endpoint
        self.credential = credential
        self.transport = transport
        self.tls = tls
        self.tags = tags
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case protocolKind
        case endpoint
        case credential
        case transport
        case tls
        case tags
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["id", "name", "protocolKind", "endpoint", "credential", "transport", "tls", "tags"],
            description: "Unknown server field"
        )
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        protocolKind = try container.decode(ProxyProtocol.self, forKey: .protocolKind)
        endpoint = try container.decode(Endpoint.self, forKey: .endpoint)
        credential = try container.decodeIfPresent(SecretReference.self, forKey: .credential)
        transport = try container.decode(TransportOptions.self, forKey: .transport)
        tls = try container.decodeIfPresent(TLSOptions.self, forKey: .tls)
        tags = try container.decode([String].self, forKey: .tags)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(protocolKind, forKey: .protocolKind)
        try container.encode(endpoint, forKey: .endpoint)
        if let credential {
            try container.encode(credential, forKey: .credential)
        } else {
            try container.encodeNil(forKey: .credential)
        }
        try container.encode(transport, forKey: .transport)
        if let tls {
            try container.encode(tls, forKey: .tls)
        } else {
            try container.encodeNil(forKey: .tls)
        }
        try container.encode(tags, forKey: .tags)
    }
}

public struct SubscriptionSource: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable, Equatable {
        case url
        case pastedText
        case file
    }

    public let kind: Kind
    public let displayValue: String
    public let secretReference: SecretReference?

    private static let invalidDisplayMetadata = "invalid source display"

    public init(kind: Kind, displayValue: String, secretReference: SecretReference? = nil) {
        self.kind = kind
        let sanitizedDisplayValue: String
        switch kind {
        case .url:
            sanitizedDisplayValue = Self.redactedURL(displayValue)
        case .pastedText:
            sanitizedDisplayValue = Self.isRawProxyShareLinkDisplayValue(displayValue) ? Self.invalidDisplayMetadata : "pasted text"
        case .file:
            sanitizedDisplayValue = Self.isRawProxyShareLinkDisplayValue(displayValue) ? Self.invalidDisplayMetadata : "file"
        }
        self.displayValue = sanitizedDisplayValue
        self.secretReference = secretReference
    }

    public static func isHTTPURL(_ value: String) -> Bool {
        guard let components = URLComponents(string: value),
              let scheme = components.scheme?.lowercased(),
              let host = components.host,
              !host.isEmpty,
              ["http", "https"].contains(scheme),
              components.user == nil,
              components.password == nil else {
            return false
        }
        return true
    }

    public static func isSanitizedURLDisplayValue(_ value: String) -> Bool {
        guard isHTTPURL(value), let components = URLComponents(string: value) else {
            return false
        }
        return components.path == "/••••••••" && components.query == nil && components.fragment == nil
    }

    public static func isRawProxyShareLinkDisplayValue(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let schemes = [
            "vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://",
            "tuic://", "naive://", "brook://", "juicity://", "anytls://"
        ]
        return schemes.contains(where: normalized.hasPrefix)
    }

    public static func isValidDisplayValue(kind: Kind, displayValue: String) -> Bool {
        switch kind {
        case .url:
            return isSanitizedURLDisplayValue(displayValue)
        case .pastedText, .file:
            return !displayValue.isEmpty && displayValue != invalidDisplayMetadata && !isRawProxyShareLinkDisplayValue(displayValue)
        }
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case displayValue
        case secretReference
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["kind", "displayValue", "secretReference"],
            description: "Unknown subscription source field"
        )
        let kind = try container.decode(Kind.self, forKey: .kind)
        let displayValue = try container.decode(String.self, forKey: .displayValue)
        let secretReference = try container.decodeIfPresent(SecretReference.self, forKey: .secretReference)
        if decoder.userInfo[canonicalStructuralDecodingKey] as? Bool != true {
            switch kind {
            case .url:
                guard secretReference != nil, Self.isHTTPURL(displayValue) else {
                    throw DecodingError.dataCorrupted(
                        DecodingError.Context(
                            codingPath: decoder.codingPath,
                            debugDescription: "URL sources require a secret reference and an HTTP(S) URL"
                        )
                    )
                }
            case .pastedText, .file:
                guard secretReference == nil, !Self.isRawProxyShareLinkDisplayValue(displayValue) else {
                    throw DecodingError.dataCorrupted(
                        DecodingError.Context(
                            codingPath: decoder.codingPath,
                            debugDescription: "Pasted and file sources cannot contain raw proxy links"
                        )
                    )
                }
            }
        }
        self.init(kind: kind, displayValue: displayValue, secretReference: secretReference)
    }

    public func encode(to encoder: Encoder) throws {
        switch kind {
        case .url:
            guard secretReference != nil, Self.isSanitizedURLDisplayValue(displayValue) else {
                throw EncodingError.invalidValue(
                    "redacted",
                    EncodingError.Context(
                        codingPath: encoder.codingPath,
                        debugDescription: "URL sources require a secret reference and sanitized HTTP(S) display metadata"
                    )
                )
            }
        case .pastedText, .file:
            guard secretReference == nil, Self.isValidDisplayValue(kind: kind, displayValue: displayValue) else {
                throw EncodingError.invalidValue(
                    "redacted",
                    EncodingError.Context(
                        codingPath: encoder.codingPath,
                        debugDescription: "Pasted and file sources require sanitized display metadata"
                    )
                )
            }
        }

        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind, forKey: .kind)
        try container.encode(displayValue, forKey: .displayValue)
        if let secretReference {
            try container.encode(secretReference, forKey: .secretReference)
        } else {
            try container.encodeNil(forKey: .secretReference)
        }
    }

    /// The one redacted URL form this repository uses.
    ///
    /// It keeps the port. `RoviaSubscription.SubscriptionRedactor` keeps it, the
    /// JSON Schema pattern admits it, `tools/ci/validate-schemas.py` derives the
    /// expected display value with it, the share-link fixtures carry it, and
    /// `PRIVACY.md` states that a redacted value keeps the scheme, host, and port.
    /// This implementation dropped it, so a config that named a port lost it while
    /// a parsed share link kept it, and the persisted value depended on which
    /// path had produced it. The port is not the secret: redaction removes the
    /// credential, and the server's port is part of the identity a screenshot
    /// already shows.
    private static func redactedURL(_ value: String) -> String {
        guard isHTTPURL(value), let components = URLComponents(string: value), let scheme = components.scheme, let host = components.host else {
            return "redacted"
        }
        let port = components.port.map { ":\($0)" } ?? ""
        return "\(scheme)://\(host)\(port)/••••••••"
    }
}

public struct RefreshPolicy: Codable, Sendable, Equatable {
    public enum Mode: String, Codable, Sendable, Equatable {
        case manual
        case interval
    }

    public let mode: Mode
    public let interval: TimeInterval?

    public init(mode: Mode, interval: TimeInterval? = nil) {
        self.mode = mode
        self.interval = interval
    }

    private enum CodingKeys: String, CodingKey {
        case mode
        case interval
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["mode", "interval"],
            description: "Unknown refresh policy field"
        )
        mode = try container.decode(Mode.self, forKey: .mode)
        interval = try container.decodeIfPresent(TimeInterval.self, forKey: .interval)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        if let interval {
            try container.encode(interval, forKey: .interval)
        } else {
            try container.encodeNil(forKey: .interval)
        }
    }
}

public struct Subscription: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var source: SubscriptionSource
    public var serverIDs: [UUID]
    public var refreshPolicy: RefreshPolicy
    public var lastRefresh: Date?
    public var contentHash: String?

    public init(
        id: UUID,
        name: String,
        source: SubscriptionSource,
        serverIDs: [UUID] = [],
        refreshPolicy: RefreshPolicy = .init(mode: .manual),
        lastRefresh: Date? = nil,
        contentHash: String? = nil
    ) {
        self.id = id
        self.name = name
        self.source = source
        self.serverIDs = serverIDs
        self.refreshPolicy = refreshPolicy
        self.lastRefresh = lastRefresh
        self.contentHash = contentHash
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case source
        case serverIDs
        case refreshPolicy
        case lastRefresh
        case contentHash
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["id", "name", "source", "serverIDs", "refreshPolicy", "lastRefresh", "contentHash"],
            description: "Unknown subscription field"
        )
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        source = try container.decode(SubscriptionSource.self, forKey: .source)
        serverIDs = try container.decode([UUID].self, forKey: .serverIDs)
        refreshPolicy = try container.decode(RefreshPolicy.self, forKey: .refreshPolicy)
        lastRefresh = try container.decodeIfPresent(Date.self, forKey: .lastRefresh)
        contentHash = try container.decodeIfPresent(String.self, forKey: .contentHash)
    }
}

public struct ServerGroup: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var mode: GroupMode
    public var members: [UUID]
    public var selectionPolicy: SelectionPolicy

    public init(id: UUID, name: String, mode: GroupMode, members: [UUID], selectionPolicy: SelectionPolicy) {
        self.id = id
        self.name = name
        self.mode = mode
        self.members = members
        self.selectionPolicy = selectionPolicy
    }

    public func contains(_ serverID: UUID) -> Bool {
        members.contains(serverID)
    }

    public func memberIndex(of serverID: UUID) -> Int? {
        members.firstIndex(of: serverID)
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case mode
        case members
        case selectionPolicy
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["id", "name", "mode", "members", "selectionPolicy"],
            description: "Unknown server group field"
        )
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        mode = try container.decode(GroupMode.self, forKey: .mode)
        members = try container.decode([UUID].self, forKey: .members)
        selectionPolicy = try container.decode(SelectionPolicy.self, forKey: .selectionPolicy)
    }
}

public struct RouteInput: Codable, Sendable, Equatable {
    public var host: String?
    public var ip: String?
    public var port: Int?
    public var network: String?

    public init(host: String? = nil, ip: String? = nil, port: Int? = nil, network: String? = nil) {
        self.host = host
        self.ip = ip
        self.port = port
        self.network = network
    }
}

public enum RouteMatcher: Codable, Sendable, Equatable {
    case domain(String)
    case domainSuffix(String)
    case ipCIDR(String)
    case port(Int)
    case portRange(lower: Int, upper: Int)
    case network(String)

    private enum CodingKeys: String, CodingKey {
        case type
        case value
        case lower
        case upper
    }

    private enum Kind: String, Codable {
        case domain
        case domainSuffix
        case ipCIDR
        case port
        case portRange
        case network
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["type", "value", "lower", "upper"],
            description: "Unknown route matcher field"
        )
        let kind = try container.decode(Kind.self, forKey: .type)
        switch kind {
        case .domain:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type", "value"], description: "Unknown domain matcher field")
            self = .domain(try container.decode(String.self, forKey: .value))
        case .domainSuffix:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type", "value"], description: "Unknown domain suffix matcher field")
            self = .domainSuffix(try container.decode(String.self, forKey: .value))
        case .ipCIDR:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type", "value"], description: "Unknown IP CIDR matcher field")
            self = .ipCIDR(try container.decode(String.self, forKey: .value))
        case .port:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type", "value"], description: "Unknown port matcher field")
            self = .port(try container.decode(Int.self, forKey: .value))
        case .portRange:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type", "lower", "upper"], description: "Unknown port range matcher field")
            self = .portRange(
                lower: try container.decode(Int.self, forKey: .lower),
                upper: try container.decode(Int.self, forKey: .upper)
            )
        case .network:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type", "value"], description: "Unknown network matcher field")
            self = .network(try container.decode(String.self, forKey: .value))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .domain(value):
            try container.encode(Kind.domain, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .domainSuffix(value):
            try container.encode(Kind.domainSuffix, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .ipCIDR(value):
            try container.encode(Kind.ipCIDR, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .port(value):
            try container.encode(Kind.port, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .portRange(lower, upper):
            try container.encode(Kind.portRange, forKey: .type)
            try container.encode(lower, forKey: .lower)
            try container.encode(upper, forKey: .upper)
        case let .network(value):
            try container.encode(Kind.network, forKey: .type)
            try container.encode(value, forKey: .value)
        }
    }
}

public enum RouteAction: Codable, Sendable, Equatable {
    case direct
    case block
    case group(UUID)

    private enum CodingKeys: String, CodingKey {
        case type
        case id
    }

    private enum Kind: String, Codable {
        case direct
        case block
        case group
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["type", "id"],
            description: "Unknown route action field"
        )
        switch try container.decode(Kind.self, forKey: .type) {
        case .direct:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type"], description: "Unknown direct route action field")
            self = .direct
        case .block:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type"], description: "Unknown block route action field")
            self = .block
        case .group:
            try CanonicalCodingSupport.rejectUnknownKeys(decoder, allowed: ["type", "id"], description: "Unknown group route action field")
            self = .group(try container.decode(UUID.self, forKey: .id))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .direct:
            try container.encode(Kind.direct, forKey: .type)
        case .block:
            try container.encode(Kind.block, forKey: .type)
        case let .group(id):
            try container.encode(Kind.group, forKey: .type)
            try container.encode(id, forKey: .id)
        }
    }
}

public struct RouteRule: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public var enabled: Bool
    public var matchers: [RouteMatcher]
    public var action: RouteAction
    public var note: String?

    public init(id: UUID, enabled: Bool, matchers: [RouteMatcher], action: RouteAction, note: String? = nil) {
        self.id = id
        self.enabled = enabled
        self.matchers = matchers
        self.action = action
        self.note = note
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case enabled
        case matchers
        case action
        case note
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["id", "enabled", "matchers", "action", "note"],
            description: "Unknown route rule field"
        )
        id = try container.decode(UUID.self, forKey: .id)
        enabled = try container.decode(Bool.self, forKey: .enabled)
        matchers = try container.decode([RouteMatcher].self, forKey: .matchers)
        action = try container.decode(RouteAction.self, forKey: .action)
        note = try container.decodeIfPresent(String.self, forKey: .note)
    }
}

public struct RouteSet: Codable, Sendable, Equatable {
    public var rules: [RouteRule]
    public var defaultAction: RouteAction

    public init(rules: [RouteRule], defaultAction: RouteAction) {
        self.rules = rules
        self.defaultAction = defaultAction
    }

    private enum CodingKeys: String, CodingKey {
        case rules
        case defaultAction
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["rules", "defaultAction"],
            description: "Unknown route set field"
        )
        rules = try container.decode([RouteRule].self, forKey: .rules)
        defaultAction = try container.decode(RouteAction.self, forKey: .defaultAction)
    }
}

/// One rule's outcome inside a `RoutingDecisionTrace`.
///
/// In memory only. See `RoutingDecisionTrace` for why this type is deliberately
/// not `Codable`.
public struct RuleEvaluation: Sendable, Equatable {
    public let ruleID: UUID
    public let matched: Bool
    public let reason: String
    public let matchedMatcher: RouteMatcher?

    public init(ruleID: UUID, matched: Bool, reason: String, matchedMatcher: RouteMatcher? = nil) {
        self.ruleID = ruleID
        self.matched = matched
        self.reason = reason
        self.matchedMatcher = matchedMatcher
    }
}

/// The full result of evaluating one input, including the input itself.
///
/// This type is an in-memory explanation and is deliberately **not** `Codable`.
///
/// It carries `input` and `normalizedInput` — the raw hostname, address, and
/// port that were evaluated — and the matcher that matched, which is a rule
/// value read from configuration. `Codable` conformance on a public type is a
/// standing invitation to write exactly those values to a file, a log, a crash
/// report, or a provider message, and nothing in the type system would stop it.
/// The redacted, serializable form of the same decision is
/// `RoviaRouting.RoutingDiagnostic`, which `RouteEvaluator.explain(_:using:context:)`
/// returns: it has four booleans instead of the input, and it is the shape
/// `schemas/control-api.schema.json` describes.
///
/// The contract, stated so a future change has to argue with it:
///
/// * a trace exists for the duration of one evaluation and is then dropped;
/// * it is never written to disk, a log, a diagnostic, or a message; and
/// * anything that needs to outlive the call converts to `RoutingDiagnostic`
///   first, which is what the app's debugger and the control API do.
public struct RoutingDecisionTrace: Sendable, Equatable {
    public let input: RouteInput
    public let normalizedInput: RouteInput
    public let evaluations: [RuleEvaluation]
    public let finalDecision: RouteAction
    public let selectedGroup: UUID?
    public let selectedServer: UUID?

    public init(
        input: RouteInput,
        normalizedInput: RouteInput,
        evaluations: [RuleEvaluation],
        finalDecision: RouteAction,
        selectedGroup: UUID? = nil,
        selectedServer: UUID? = nil
    ) {
        self.input = input
        self.normalizedInput = normalizedInput
        self.evaluations = evaluations
        self.finalDecision = finalDecision
        self.selectedGroup = selectedGroup
        self.selectedServer = selectedServer
    }
}

public struct DNSPolicy: Codable, Sendable, Equatable {
    public enum Mode: String, Codable, Sendable, Equatable {
        case system
        case tunnel
        case custom
    }

    public var mode: Mode
    public var servers: [String]

    public init(mode: Mode, servers: [String] = []) {
        self.mode = mode
        self.servers = servers
    }

    private enum CodingKeys: String, CodingKey {
        case mode
        case servers
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["mode", "servers"],
            description: "Unknown DNS policy field"
        )
        mode = try container.decode(Mode.self, forKey: .mode)
        servers = try container.decode([String].self, forKey: .servers)
    }
}

public struct PrivacyPolicy: Codable, Sendable, Equatable {
    public enum DiagnosticsRetention: String, Codable, Sendable, Equatable {
        case memoryOnly
        case userExport
    }

    public let telemetryEnabled: Bool
    public let trafficLogging: Bool
    public let domainHistory: Bool
    public let diagnosticsRetention: DiagnosticsRetention
    public let redactServerAddresses: Bool
    public let redactCredentials: Bool

    public init() {
        telemetryEnabled = false
        trafficLogging = false
        domainHistory = false
        diagnosticsRetention = .memoryOnly
        redactServerAddresses = true
        redactCredentials = true
    }

    private enum CodingKeys: String, CodingKey {
        case telemetryEnabled
        case trafficLogging
        case domainHistory
        case diagnosticsRetention
        case redactServerAddresses
        case redactCredentials
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try CanonicalCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: [
                "telemetryEnabled", "trafficLogging", "domainHistory", "diagnosticsRetention",
                "redactServerAddresses", "redactCredentials"
            ],
            description: "Unknown privacy policy field"
        )
        let telemetryEnabled = try container.decode(Bool.self, forKey: .telemetryEnabled)
        let trafficLogging = try container.decode(Bool.self, forKey: .trafficLogging)
        let domainHistory = try container.decode(Bool.self, forKey: .domainHistory)
        let diagnosticsRetention = try container.decode(DiagnosticsRetention.self, forKey: .diagnosticsRetention)
        let redactServerAddresses = try container.decode(Bool.self, forKey: .redactServerAddresses)
        let redactCredentials = try container.decode(Bool.self, forKey: .redactCredentials)

        if decoder.userInfo[canonicalStructuralDecodingKey] as? Bool != true {
            guard !telemetryEnabled,
                  !trafficLogging,
                  !domainHistory,
                  redactServerAddresses,
                  redactCredentials else {
                throw DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: decoder.codingPath,
                        debugDescription: "MVP privacy policy cannot enable collection or disable redaction"
                    )
                )
            }
        }

        self.telemetryEnabled = telemetryEnabled
        self.trafficLogging = trafficLogging
        self.domainHistory = domainHistory
        self.diagnosticsRetention = diagnosticsRetention
        self.redactServerAddresses = redactServerAddresses
        self.redactCredentials = redactCredentials
    }
}

public struct AppConfig: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public var subscriptions: [Subscription]
    public var groups: [ServerGroup]
    public var routing: RouteSet
    public var dns: DNSPolicy
    public var privacy: PrivacyPolicy
    public var servers: [Server]

    public init(
        schemaVersion: Int,
        subscriptions: [Subscription],
        groups: [ServerGroup],
        routing: RouteSet,
        dns: DNSPolicy,
        privacy: PrivacyPolicy,
        servers: [Server] = []
    ) {
        self.schemaVersion = schemaVersion
        self.subscriptions = subscriptions
        self.groups = groups
        self.routing = routing
        self.dns = dns
        self.privacy = privacy
        self.servers = servers
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case subscriptions
        case groups
        case routing
        case dns
        case privacy
        case servers
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

    public init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: DynamicCodingKey.self)
        let allowed = Set([
            CodingKeys.schemaVersion.rawValue,
            CodingKeys.subscriptions.rawValue,
            CodingKeys.groups.rawValue,
            CodingKeys.routing.rawValue,
            CodingKeys.dns.rawValue,
            CodingKeys.privacy.rawValue,
            CodingKeys.servers.rawValue
        ])
        if let unknown = dynamic.allKeys.first(where: { !allowed.contains($0.stringValue) }) {
            throw DecodingError.dataCorruptedError(
                forKey: unknown,
                in: dynamic,
                debugDescription: "Unknown AppConfig field"
            )
        }

        let container = try decoder.container(keyedBy: CodingKeys.self)
        let schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == CanonicalConfigLoader.currentSchemaVersion else {
            throw CanonicalConfigError.invalidSchemaVersion(schemaVersion)
        }
        self.schemaVersion = schemaVersion
        subscriptions = try container.decode([Subscription].self, forKey: .subscriptions)
        groups = try container.decode([ServerGroup].self, forKey: .groups)
        routing = try container.decode(RouteSet.self, forKey: .routing)
        dns = try container.decode(DNSPolicy.self, forKey: .dns)
        privacy = try container.decode(PrivacyPolicy.self, forKey: .privacy)
        servers = try container.decode([Server].self, forKey: .servers)
    }

    public func encode(to encoder: Encoder) throws {
        try validateForPersistence()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(subscriptions, forKey: .subscriptions)
        try container.encode(groups, forKey: .groups)
        try container.encode(routing, forKey: .routing)
        try container.encode(dns, forKey: .dns)
        try container.encode(privacy, forKey: .privacy)
        try container.encode(servers, forKey: .servers)
    }

    public func validateForPersistence() throws {
        let report = validationReport()
        guard !report.isValid else { return }

        if report.issues.contains(where: { $0.code == ConfigValidationCode.invalidSchemaVersion.rawValue }) {
            throw CanonicalConfigError.invalidSchemaVersion(schemaVersion)
        }
        if report.issues.contains(where: { $0.code == ConfigValidationCode.unsafePrivacyPolicy.rawValue }) {
            throw CanonicalConfigError.unsafePrivacyPolicy
        }

        let serverIDs = Set(servers.map(\.id))
        if report.issues.contains(where: { $0.code == ConfigValidationCode.invalidServerPort.rawValue }),
           let server = servers.first(where: { !(1...65_535).contains($0.endpoint.port) }) {
            throw CanonicalConfigError.invalidServerPort(server.endpoint.port)
        }
        if report.issues.contains(where: { $0.code == ConfigValidationCode.duplicateServerID.rawValue }),
           let duplicate = duplicateServerID() {
            throw CanonicalConfigError.duplicateServerID(duplicate)
        }
        if report.issues.contains(where: { $0.code == ConfigValidationCode.unknownServerReference.rawValue }),
           let reference = firstUnknownServerReference(serverIDs: serverIDs) {
            throw CanonicalConfigError.unknownServerReference(reference)
        }
        if report.issues.contains(where: { $0.code == ConfigValidationCode.unknownGroupReference.rawValue }),
           let reference = firstUnknownGroupReference() {
            throw CanonicalConfigError.unknownGroupReference(reference)
        }
        throw ConfigValidationError(report: report)
    }

    private func duplicateServerID() -> UUID? {
        var seen = Set<UUID>()
        for server in servers where !seen.insert(server.id).inserted {
            return server.id
        }
        return nil
    }

    private func firstUnknownServerReference(serverIDs: Set<UUID>) -> UUID? {
        for subscription in subscriptions {
            if let reference = subscription.serverIDs.first(where: { !serverIDs.contains($0) }) {
                return reference
            }
        }
        for group in groups {
            if let reference = group.members.first(where: { !serverIDs.contains($0) }) {
                return reference
            }
        }
        return nil
    }

    private func firstUnknownGroupReference() -> UUID? {
        let groupIDs = Set(groups.map(\.id))
        for rule in routing.rules {
            if case let .group(groupID) = rule.action, !groupIDs.contains(groupID) {
                return groupID
            }
        }
        if case let .group(groupID) = routing.defaultAction, !groupIDs.contains(groupID) {
            return groupID
        }
        return nil
    }
}
