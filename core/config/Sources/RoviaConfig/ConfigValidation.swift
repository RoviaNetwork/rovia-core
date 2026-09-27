import Foundation

public enum ConfigValidationSeverity: String, Codable, Sendable, Equatable {
    case error
    case warning
}

public enum ConfigValidationCode: String, Codable, Sendable, Equatable {
    case invalidSchemaVersion = "invalidSchemaVersion"
    case duplicateServerID = "duplicateServerID"
    case duplicateSubscriptionID = "duplicateSubscriptionID"
    case duplicateGroupID = "duplicateGroupID"
    case duplicateRouteRuleID = "duplicateRouteRuleID"
    case unknownServerReference = "unknownServerReference"
    case unknownGroupReference = "unknownGroupReference"
    case invalidServerPort = "invalidServerPort"
    case invalidServer = "invalidServer"
    case invalidSubscription = "invalidSubscription"
    case invalidGroup = "invalidGroup"
    case invalidRouteMatcher = "invalidRouteMatcher"
    case invalidRouteRule = "invalidRouteRule"
    case invalidRefreshPolicy = "invalidRefreshPolicy"
    case missingSourceSecretReference = "missingSourceSecretReference"
    case invalidSecretReferenceKey = "invalidSecretReferenceKey"
    case invalidSource = "invalidSource"
    case invalidSourceDisplay = "invalidSourceDisplay"
    case unsafeTransportOption = "unsafeTransportOption"
    case invalidDNS = "invalidDNS"
    case unsafePrivacyPolicy = "unsafePrivacyPolicy"
}

public struct ConfigValidationIssue: Codable, Sendable, Equatable {
    public typealias Severity = ConfigValidationSeverity

    public let code: String
    public let path: String
    public let severity: ConfigValidationSeverity
    public let message: String

    public init(
        code: String,
        path: String,
        severity: ConfigValidationSeverity = .error,
        message: String
    ) {
        self.code = code
        self.path = path
        self.severity = severity
        self.message = message
    }

    public init(
        code: String,
        jsonPath: String,
        severity: ConfigValidationSeverity = .error,
        message: String
    ) {
        self.init(code: code, path: jsonPath, severity: severity, message: message)
    }

    public var jsonPath: String { path }
}

public struct ConfigValidationReport: Codable, Sendable, Equatable {
    public let issues: [ConfigValidationIssue]

    public init(issues: [ConfigValidationIssue] = []) {
        self.issues = issues
    }

    public var isValid: Bool {
        !issues.contains { $0.severity == .error }
    }

    public var valid: Bool { isValid }

    public var hasErrors: Bool { !isValid }

    public var errors: [ConfigValidationIssue] {
        issues.filter { $0.severity == .error }
    }

    public var warnings: [ConfigValidationIssue] {
        issues.filter { $0.severity == .warning }
    }
}

public struct ConfigValidationError: Error, Equatable, Sendable, CustomStringConvertible, LocalizedError {
    public let report: ConfigValidationReport

    public init(report: ConfigValidationReport) {
        self.report = report
    }

    public var issues: [ConfigValidationIssue] { report.issues }

    public var description: String {
        "Configuration validation failed with \(report.errors.count) error(s)."
    }

    public var errorDescription: String? { description }
}

public enum CanonicalRouteValidationError: Error, Equatable, Sendable {
    case invalidPort(Int)
    case invalidCIDR(String)
    case invalidMatcher(String)
    case invalidIPAddress(String)
}

public struct CanonicalCIDR: Sendable, Equatable {
    public let address: [UInt8]
    public let prefix: Int

    public init(address: [UInt8], prefix: Int) {
        self.address = address
        self.prefix = prefix
    }
}

public enum CanonicalRouteMatcherValidator {
    public static func validate(_ matcher: RouteMatcher) throws {
        switch matcher {
        case let .domain(value):
            guard isDomain(normalizeDomain(value) ?? "") else {
                throw CanonicalRouteValidationError.invalidMatcher("domain")
            }
        case let .domainSuffix(value):
            guard isDomain(normalizeDomain(value) ?? "") else {
                throw CanonicalRouteValidationError.invalidMatcher("domainSuffix")
            }
        case let .ipCIDR(value):
            _ = try parseCIDR(value)
        case let .port(value):
            guard (1...65_535).contains(value) else {
                throw CanonicalRouteValidationError.invalidPort(value)
            }
        case let .portRange(lower, upper):
            guard (1...65_535).contains(lower) else {
                throw CanonicalRouteValidationError.invalidPort(lower)
            }
            guard (1...65_535).contains(upper) else {
                throw CanonicalRouteValidationError.invalidPort(upper)
            }
            guard lower <= upper else {
                throw CanonicalRouteValidationError.invalidMatcher("portRange")
            }
        case let .network(value):
            guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
                throw CanonicalRouteValidationError.invalidMatcher("network")
            }
        }
    }

    public static func validate(_ matchers: [RouteMatcher]) throws {
        for matcher in matchers {
            try validate(matcher)
        }
    }

    /// The domain form used for comparison: trimmed, lowercased, one trailing
    /// dot removed.
    ///
    /// Degenerate input returns nil rather than a value. It used to remove one
    /// trailing dot and return whatever was left, so `".."` became `"."` and
    /// `"..."` became `".."` — non-empty strings that describe no host and that
    /// a host comparison could match. `RouteEvaluator` normalises both sides of
    /// a domain comparison with this function, so a degenerate matcher or input
    /// compared equal to a name nobody can have. A name with an empty label is
    /// not a name.
    public static func normalizeDomain(_ value: String) -> String? {
        var result = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if result.hasSuffix(".") {
            result.removeLast()
        }
        guard !result.isEmpty, !result.hasPrefix("."), !result.contains("..") else {
            return nil
        }
        return result
    }

    /// The canonical text for an address, or nil.
    ///
    /// An IPv4-mapped address normalises to the dotted-quad it maps, so the
    /// canonical form of `::ffff:1.2.3.4` is `1.2.3.4` and everything downstream
    /// — the persisted input, the diagnostic, the rule comparison — sees one
    /// spelling of the address.
    public static func normalizeIPAddress(_ value: String) -> String? {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard let bytes = parseIPAddress(normalized) else { return nil }
        if bytes.count == 4 {
            return bytes.map(String.init).joined(separator: ".")
        }
        return normalized
    }

    /// The bytes an address denotes, or nil.
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) is accepted and returns the
    /// four bytes of the IPv4 address it maps. It is a routine form — a dual-stack
    /// socket hands one out — and before this it returned nil, which made
    /// `RouteEvaluator` throw `invalidIPAddress` for a perfectly routable
    /// destination. The policy is accept-and-normalise, not refuse: the mapped
    /// form and the plain form denote the same address, so the mapped form is
    /// compared as IPv4. The consequence is recorded in
    /// `docs/architecture/next-spikes.md`: an IPv6 rule such as `::/0` does not
    /// match a mapped input, because the candidate is four bytes and the network
    /// is sixteen. That is the safe direction — a mapped address is matched by the
    /// IPv4 rules that describe it, and a rule that means "all IPv6" does not
    /// silently capture it.
    public static func parseIPAddress(_ value: String) -> [UInt8]? {
        if let ipv4 = parseIPv4(value) { return ipv4 }
        if let mapped = parseIPv4Mapped(value) { return mapped }
        return parseIPv6(value)
    }

    /// The IPv4 address an IPv4-mapped IPv6 address denotes, if that is what this is.
    private static func parseIPv4Mapped(_ value: String) -> [UInt8]? {
        let prefix = "::ffff:"
        let lowered = value.lowercased()
        guard lowered.hasPrefix(prefix) else { return nil }
        return parseIPv4(String(lowered.dropFirst(prefix.count)))
    }

    public static func parseCIDR(_ value: String) throws -> CanonicalCIDR {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]) else {
            throw CanonicalRouteValidationError.invalidCIDR(value)
        }

        let address = String(parts[0]).lowercased()
        if let network = parseIPv4(address), (0...32).contains(prefix) {
            return CanonicalCIDR(address: network, prefix: prefix)
        }
        if let network = parseIPv6(address), (0...128).contains(prefix) {
            return CanonicalCIDR(address: network, prefix: prefix)
        }
        throw CanonicalRouteValidationError.invalidCIDR(value)
    }

    public static func cidr(_ value: String, contains ip: String) throws -> Bool {
        let parsed = try parseCIDR(value)
        guard let candidate = parseIPAddress(ip) else { return false }
        guard parsed.address.count == candidate.count else { return false }
        for index in candidate.indices {
            let remaining = parsed.prefix - index * 8
            if remaining <= 0 { break }
            let bits = min(8, remaining)
            let mask: UInt8 = bits == 8 ? 0xff : UInt8(truncatingIfNeeded: 0xff << (8 - bits))
            if candidate[index] & mask != parsed.address[index] & mask {
                return false
            }
        }
        return true
    }

    private static func isDomain(_ value: String) -> Bool {
        guard value.count <= 253, !value.contains(where: { $0.isWhitespace || $0.isNewline }) else {
            return false
        }
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }
        return labels.allSatisfy { label in
            guard (1...63).contains(label.count),
                  label.first != "-",
                  label.last != "-" else {
                return false
            }
            return label.allSatisfy { character in
                character.isASCII && (character.isLetter || character.isNumber || character == "-")
            }
        }
    }

    private static func parseIPv4(_ value: String) -> [UInt8]? {
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for component in components {
            let text = String(component)
            guard let byte = UInt8(text), String(byte) == text else { return nil }
            bytes.append(byte)
        }
        return bytes
    }

    private static func parseIPv6(_ value: String) -> [UInt8]? {
        if value.contains("%") { return nil }
        var normalized = value
        if normalized.contains(".") {
            guard let lastColon = normalized.lastIndex(of: ":") else { return nil }
            let suffixStart = normalized.index(after: lastColon)
            guard let ipv4 = parseIPv4(String(normalized[suffixStart...])) else { return nil }
            let high = UInt16(ipv4[0]) << 8 | UInt16(ipv4[1])
            let low = UInt16(ipv4[2]) << 8 | UInt16(ipv4[3])
            normalized = String(normalized[..<lastColon]) + String(format: "%x:%x", high, low)
        }

        let halves = normalized.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        let left = parseHextets(halves[0])
        let right = halves.count == 2 ? parseHextets(halves[1]) : []
        guard let left, let right else { return nil }

        if halves.count == 1 {
            guard left.count == 8 else { return nil }
            return bytes(from: left)
        }

        let missing = 8 - left.count - right.count
        guard missing >= 1, left.count + right.count <= 7 else { return nil }
        let hextets = left + Array(repeating: 0, count: missing) + right
        return bytes(from: hextets)
    }

    private static func parseHextets(_ value: String) -> [UInt16]? {
        if value.isEmpty { return [] }
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count <= 8 else { return nil }
        var result: [UInt16] = []
        for part in parts {
            guard !part.isEmpty, part.count <= 4, let number = UInt16(part, radix: 16) else {
                return nil
            }
            result.append(number)
        }
        return result
    }

    private static func bytes(from hextets: [UInt16]) -> [UInt8] {
        hextets.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xff)] }
    }
}

public enum CanonicalConfigLoader {
    public static let currentSchemaVersion = 1

    public static func load(_ data: Data) throws -> AppConfig {
        let object = try rootObject(from: data)
        let version = try schemaVersion(in: object)
        guard version == currentSchemaVersion else {
            throw CanonicalConfigError.invalidSchemaVersion(version)
        }
        try CanonicalJSONShapeValidator.validate(object)
        let config: AppConfig
        do {
            config = try JSONCoding.structuralDecoder().decode(AppConfig.self, from: data)
        } catch {
            throw structuralError(from: error)
        }
        return try config.validated()
    }

    public static func load(_ string: String) throws -> AppConfig {
        try load(Data(string.utf8))
    }

    public static func load(_ url: URL) throws -> AppConfig {
        try load(Data(contentsOf: url))
    }

    public static func load(contentsOf url: URL) throws -> AppConfig {
        try load(Data(contentsOf: url))
    }

    public static func migrate(_ data: Data) throws -> Data {
        let object = try rootObject(from: data)
        let version = try schemaVersion(in: object)
        guard version == currentSchemaVersion else {
            throw CanonicalConfigError.invalidSchemaVersion(version)
        }
        try CanonicalJSONShapeValidator.validate(object)
        let config: AppConfig
        do {
            config = try JSONCoding.structuralDecoder().decode(AppConfig.self, from: data)
        } catch {
            throw structuralError(from: error)
        }
        _ = try config.validated()
        return data
    }

    public static func migrate(_ config: AppConfig) throws -> AppConfig {
        try config.validated()
    }

    private static func rootObject(from data: Data) throws -> [String: Any] {
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any] else {
            throw CanonicalConfigError.invalidJSON
        }
        return dictionary
    }

    private static func schemaVersion(in object: [String: Any]) throws -> Int {
        guard let number = object["schemaVersion"] as? NSNumber,
              String(cString: number.objCType) != "c",
              number.doubleValue == number.doubleValue.rounded() else {
            throw CanonicalConfigError.missingSchemaVersion
        }
        return number.intValue
    }

    private static func structuralError(from error: Error) -> CanonicalConfigError {
        guard let decodingError = error as? DecodingError else {
            return .invalidField(path: "config")
        }
        let codingPath: [CodingKey]
        switch decodingError {
        case let .dataCorrupted(context):
            codingPath = context.codingPath
        case let .keyNotFound(_, context):
            codingPath = context.codingPath
        case let .typeMismatch(_, context):
            codingPath = context.codingPath
        case let .valueNotFound(_, context):
            codingPath = context.codingPath
        @unknown default:
            codingPath = []
        }
        let path = codingPath.map { key in
            if let intValue = key.intValue {
                return String(intValue)
            }
            return key.stringValue
        }.joined(separator: ".")
        return .invalidField(path: path.isEmpty ? "config" : path)
    }
}

extension AppConfig {
    public func validationReport() -> ConfigValidationReport {
        var issues: [ConfigValidationIssue] = []

        func add(_ code: ConfigValidationCode, _ path: String, _ message: String) {
            issues.append(ConfigValidationIssue(code: code.rawValue, path: path, message: message))
        }

        if schemaVersion != CanonicalConfigLoader.currentSchemaVersion {
            add(.invalidSchemaVersion, "schemaVersion", "The configuration schema version is not supported.")
        }

        if privacy.telemetryEnabled || privacy.trafficLogging || privacy.domainHistory ||
            !privacy.redactServerAddresses || !privacy.redactCredentials {
            add(.unsafePrivacyPolicy, "privacy", "The privacy policy cannot enable collection or disable redaction.")
        }

        var serverIDs = Set<UUID>()
        for (index, server) in servers.enumerated() {
            let path = "servers[\(index)]"
            if server.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                add(.invalidServer, "\(path).name", "Server names must not be empty.")
            }
            if !(1...65_535).contains(server.endpoint.port) {
                add(.invalidServerPort, "\(path).endpoint.port", "Server ports must be between 1 and 65535.")
            }
            if server.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                add(.invalidServer, "\(path).endpoint.host", "Server hosts must not be empty.")
            }
            if !serverIDs.insert(server.id).inserted {
                add(.duplicateServerID, "\(path).id", "Server IDs must be unique.")
            }
            if server.transport.kind.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                add(.invalidServer, "\(path).transport.kind", "Transport kinds must not be empty.")
            }
            if TransportOptions.secretBearingKey(in: server.transport.options) != nil {
                add(.unsafeTransportOption, "\(path).transport.options", "Transport options cannot contain secret-bearing keys.")
            }
            if let credential = server.credential, !SecretReference.isValidKey(credential.key) {
                add(
                    .invalidSecretReferenceKey,
                    "\(path).credential.key",
                    "A secret reference key must be 1 to \(SecretReference.maximumKeyBytes) printable ASCII characters."
                )
            }
        }

        var subscriptionIDs = Set<UUID>()
        for (index, subscription) in subscriptions.enumerated() {
            let path = "subscriptions[\(index)]"
            if !subscriptionIDs.insert(subscription.id).inserted {
                add(.duplicateSubscriptionID, "\(path).id", "Subscription IDs must be unique.")
            }
            if subscription.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                add(.invalidSubscription, "\(path).name", "Subscription names must not be empty.")
            }
            var seenServerIDs = Set<UUID>()
            for (serverIndex, serverID) in subscription.serverIDs.enumerated() {
                let serverPath = "\(path).serverIDs[\(serverIndex)]"
                if !seenServerIDs.insert(serverID).inserted {
                    add(.invalidSubscription, serverPath, "Subscription server references must be unique.")
                }
                if !serverIDs.contains(serverID) {
                    add(.unknownServerReference, serverPath, "Subscription references an unknown server.")
                }
            }
            validateSource(subscription.source, path: "\(path).source", add: add)
            validateRefresh(subscription.refreshPolicy, path: "\(path).refreshPolicy", add: add)
        }

        var groupIDs = Set<UUID>()
        for (index, group) in groups.enumerated() {
            let path = "groups[\(index)]"
            if !groupIDs.insert(group.id).inserted {
                add(.duplicateGroupID, "\(path).id", "Group IDs must be unique.")
            }
            if group.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                add(.invalidGroup, "\(path).name", "Group names must not be empty.")
            }
            if group.members.isEmpty {
                add(.invalidGroup, "\(path).members", "Groups must contain at least one server.")
            }
            var seenMembers = Set<UUID>()
            for (memberIndex, memberID) in group.members.enumerated() {
                let memberPath = "\(path).members[\(memberIndex)]"
                if !seenMembers.insert(memberID).inserted {
                    add(.invalidGroup, memberPath, "Group server references must be unique.")
                }
                if !serverIDs.contains(memberID) {
                    add(.unknownServerReference, memberPath, "Group references an unknown server.")
                }
            }
            if group.mode != selectionMode(for: group.selectionPolicy) {
                add(.invalidGroup, "\(path).selectionPolicy", "Group mode and selection policy must agree.")
            }
        }

        var routeRuleIDs = Set<UUID>()
        for (index, rule) in routing.rules.enumerated() {
            let path = "routing.rules[\(index)]"
            if !routeRuleIDs.insert(rule.id).inserted {
                add(.duplicateRouteRuleID, "\(path).id", "Route rule IDs must be unique.")
            }
            if rule.matchers.isEmpty {
                add(.invalidRouteRule, "\(path).matchers", "Route rules must contain at least one matcher.")
            }
            for (matcherIndex, matcher) in rule.matchers.enumerated() {
                do {
                    try CanonicalRouteMatcherValidator.validate(matcher)
                } catch {
                    add(.invalidRouteMatcher, "\(path).matchers[\(matcherIndex)]", "The route matcher is invalid.")
                }
            }
            validateAction(rule.action, path: "\(path).action", groupIDs: groupIDs, add: add)
        }
        validateAction(routing.defaultAction, path: "routing.defaultAction", groupIDs: groupIDs, add: add)

        if dns.mode == .custom && dns.servers.isEmpty {
            add(.invalidDNS, "dns.servers", "Custom DNS policies require at least one server.")
        }
        for (index, server) in dns.servers.enumerated() where server.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            add(.invalidDNS, "dns.servers[\(index)]", "DNS server values must not be empty.")
        }

        return ConfigValidationReport(issues: issues)
    }

    public func validated() throws -> AppConfig {
        let report = validationReport()
        guard report.isValid else {
            throw ConfigValidationError(report: report)
        }
        return self
    }

    private func selectionMode(for policy: SelectionPolicy) -> GroupMode {
        switch policy {
        case .manual: .manual
        case .lowestLatency: .lowestLatency
        case .failover: .failover
        }
    }

    private func validateSource(
        _ source: SubscriptionSource,
        path: String,
        add: (ConfigValidationCode, String, String) -> Void
    ) {
        switch source.kind {
        case .url:
            if source.secretReference == nil {
                add(.missingSourceSecretReference, "\(path).secretReference", "URL sources require a secret reference.")
            }
        case .pastedText, .file:
            if source.secretReference != nil {
                add(.invalidSource, "\(path).secretReference", "Only URL sources may contain a secret reference.")
            }
        }
        if source.displayValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            add(.invalidSource, "\(path).displayValue", "Source display metadata must not be empty.")
        }
        if !SubscriptionSource.isValidDisplayValue(kind: source.kind, displayValue: source.displayValue) {
            add(.invalidSourceDisplay, "\(path).displayValue", "Source display metadata is not sanitized for its kind.")
        }
        if let reference = source.secretReference, !SecretReference.isValidKey(reference.key) {
            add(
                .invalidSecretReferenceKey,
                "\(path).secretReference.key",
                "A secret reference key must be 1 to \(SecretReference.maximumKeyBytes) printable ASCII characters."
            )
        }
    }

    private func validateRefresh(
        _ policy: RefreshPolicy,
        path: String,
        add: (ConfigValidationCode, String, String) -> Void
    ) {
        switch policy.mode {
        case .manual:
            if policy.interval != nil {
                add(.invalidRefreshPolicy, "\(path).interval", "Manual refresh policies cannot define an interval.")
            }
        case .interval:
            guard let interval = policy.interval,
                  interval.isFinite,
                  interval > 0 else {
                add(.invalidRefreshPolicy, "\(path).interval", "Interval refresh policies require a positive finite interval.")
                return
            }
        }
    }

    private func validateAction(
        _ action: RouteAction,
        path: String,
        groupIDs: Set<UUID>,
        add: (ConfigValidationCode, String, String) -> Void
    ) {
        if case let .group(groupID) = action, !groupIDs.contains(groupID) {
            add(.unknownGroupReference, "\(path).id", "Route action references an unknown group.")
        }
    }
}

enum CanonicalJSONShapeValidator {
    static func validate(_ value: Any) throws {
        let root = try object(value, path: "$")
        try keys(root, path: "$", allowed: [
            "schemaVersion", "subscriptions", "servers", "groups", "routing", "dns", "privacy"
        ], required: [
            "schemaVersion", "subscriptions", "servers", "groups", "routing", "dns", "privacy"
        ])
        try version(root["schemaVersion"]!, path: "schemaVersion")
        try array(root["subscriptions"]!, path: "subscriptions", element: validateSubscription)
        try array(root["servers"]!, path: "servers", element: validateServer)
        try array(root["groups"]!, path: "groups", element: validateGroup)
        try routeSet(root["routing"]!, path: "routing")
        try dnsPolicy(root["dns"]!, path: "dns")
        try privacyPolicy(root["privacy"]!, path: "privacy")
    }

    private static func validateSubscription(_ value: Any) throws {
        let object = try keyed(value, path: "subscriptions[]")
        try keys(object, path: "subscriptions[]", allowed: [
            "id", "name", "source", "serverIDs", "refreshPolicy", "lastRefresh", "contentHash"
        ], required: ["id", "name", "source", "serverIDs", "refreshPolicy"])
        try uuid(object["id"]!, path: "subscriptions[].id")
        try string(object["name"]!, path: "subscriptions[].name")
        try source(object["source"]!, path: "subscriptions[].source")
        try uuidArray(object["serverIDs"]!, path: "subscriptions[].serverIDs")
        try refreshPolicy(object["refreshPolicy"]!, path: "subscriptions[].refreshPolicy")
        try nullableDate(object["lastRefresh"], path: "subscriptions[].lastRefresh")
        try nullableString(object["contentHash"], path: "subscriptions[].contentHash")
    }

    private static func validateServer(_ value: Any) throws {
        let object = try keyed(value, path: "servers[]")
        try keys(object, path: "servers[]", allowed: [
            "id", "name", "protocolKind", "endpoint", "credential", "transport", "tls", "tags"
        ], required: ["id", "name", "protocolKind", "endpoint", "credential", "transport", "tls", "tags"])
        try uuid(object["id"]!, path: "servers[].id")
        try string(object["name"]!, path: "servers[].name")
        try enumeration(object["protocolKind"]!, path: "servers[].protocolKind", values: ["vless", "vmess", "trojan", "shadowsocks"])
        try endpoint(object["endpoint"]!, path: "servers[].endpoint")
        try nullableSecret(object["credential"]!, path: "servers[].credential")
        try transport(object["transport"]!, path: "servers[].transport")
        try nullableTLS(object["tls"]!, path: "servers[].tls")
        try stringArray(object["tags"]!, path: "servers[].tags")
    }

    private static func validateGroup(_ value: Any) throws {
        let object = try keyed(value, path: "groups[]")
        try keys(object, path: "groups[]", allowed: ["id", "name", "mode", "members", "selectionPolicy"], required: ["id", "name", "mode", "members", "selectionPolicy"])
        try uuid(object["id"]!, path: "groups[].id")
        try string(object["name"]!, path: "groups[].name")
        try enumeration(object["mode"]!, path: "groups[].mode", values: ["manual", "lowestLatency", "failover"])
        try uuidArray(object["members"]!, path: "groups[].members")
        try enumeration(object["selectionPolicy"]!, path: "groups[].selectionPolicy", values: ["manual", "lowestLatency", "failover"])
    }

    private static func routeSet(_ value: Any, path: String) throws {
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: ["rules", "defaultAction"], required: ["rules", "defaultAction"])
        try array(object["rules"]!, path: "\(path).rules", element: routeRule)
        try routeAction(object["defaultAction"]!, path: "\(path).defaultAction")
    }

    private static func routeRule(_ value: Any) throws {
        let path = "routing.rules[]"
        let object = try keyed(value, path: path)
        try keys(object, path: path, allowed: ["id", "enabled", "matchers", "action", "note"], required: ["id", "enabled", "matchers", "action"])
        try uuid(object["id"]!, path: "\(path).id")
        guard let enabled = object["enabled"] as? Bool else { throw CanonicalConfigError.invalidField(path: "\(path).enabled") }
        _ = enabled
        try array(object["matchers"]!, path: "\(path).matchers", element: routeMatcher)
        try routeAction(object["action"]!, path: "\(path).action")
        try nullableString(object["note"], path: "\(path).note")
    }

    private static func routeMatcher(_ value: Any) throws {
        let path = "routing.rules[].matchers[]"
        let object = try keyed(value, path: path)
        guard let type = object["type"] as? String else { throw CanonicalConfigError.invalidField(path: "\(path).type") }
        switch type {
        case "domain", "domainSuffix", "network":
            try keys(object, path: path, allowed: ["type", "value"], required: ["type", "value"])
            try string(object["value"]!, path: "\(path).value")
        case "ipCIDR":
            try keys(object, path: path, allowed: ["type", "value"], required: ["type", "value"])
            try string(object["value"]!, path: "\(path).value")
        case "port":
            try keys(object, path: path, allowed: ["type", "value"], required: ["type", "value"])
            try port(object["value"]!, path: "\(path).value")
        case "portRange":
            try keys(object, path: path, allowed: ["type", "lower", "upper"], required: ["type", "lower", "upper"])
            try port(object["lower"]!, path: "\(path).lower")
            try port(object["upper"]!, path: "\(path).upper")
        default:
            throw CanonicalConfigError.invalidField(path: "\(path).type")
        }
    }

    private static func routeAction(_ value: Any, path: String) throws {
        let object = try keyed(value, path: path)
        guard let type = object["type"] as? String else { throw CanonicalConfigError.invalidField(path: path) }
        switch type {
        case "direct", "block":
            try keys(object, path: path, allowed: ["type"], required: ["type"])
        case "group":
            try keys(object, path: path, allowed: ["type", "id"], required: ["type", "id"])
            try uuid(object["id"]!, path: "\(path).id")
        default:
            throw CanonicalConfigError.invalidField(path: "\(path).type")
        }
    }

    private static func source(_ value: Any, path: String) throws {
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: ["kind", "displayValue", "secretReference"], required: ["kind", "displayValue"])
        guard let kind = object["kind"] as? String,
              ["url", "pastedText", "file"].contains(kind) else {
            throw CanonicalConfigError.invalidField(path: "\(path).kind")
        }
        let displayValue = try stringValue(object["displayValue"]!, path: "\(path).displayValue")
        switch kind {
        case "url":
            guard SubscriptionSource.isSanitizedURLDisplayValue(displayValue) else {
                throw CanonicalConfigError.invalidField(path: "\(path).displayValue")
            }
        case "pastedText", "file":
            guard !SubscriptionSource.isRawProxyShareLinkDisplayValue(displayValue) else {
                throw CanonicalConfigError.invalidField(path: "\(path).displayValue")
            }
        default:
            throw CanonicalConfigError.invalidField(path: "\(path).kind")
        }
        if let reference = object["secretReference"], !(reference is NSNull) {
            try secretReference(reference, path: "\(path).secretReference")
        }
    }

    private static func refreshPolicy(_ value: Any, path: String) throws {
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: ["mode", "interval"], required: ["mode"])
        guard let mode = object["mode"] as? String, ["manual", "interval"].contains(mode) else {
            throw CanonicalConfigError.invalidField(path: "\(path).mode")
        }
        if let interval = object["interval"], !(interval is NSNull) {
            guard let number = interval as? NSNumber,
                  !isBoolean(number),
                  number.doubleValue.isFinite else {
                throw CanonicalConfigError.invalidField(path: "\(path).interval")
            }
        }
    }

    private static func endpoint(_ value: Any, path: String) throws {
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: ["host", "port"], required: ["host", "port"])
        try string(object["host"]!, path: "\(path).host")
        try port(object["port"]!, path: "\(path).port")
    }

    private static func transport(_ value: Any, path: String) throws {
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: ["kind", "options"], required: ["kind", "options"])
        try string(object["kind"]!, path: "\(path).kind")
        guard let options = object["options"] as? [String: Any] else {
            throw CanonicalConfigError.invalidField(path: "\(path).options")
        }
        for option in options.values {
            guard option is String else {
                throw CanonicalConfigError.invalidField(path: "\(path).options")
            }
        }
    }

    private static func nullableTLS(_ value: Any, path: String) throws {
        if value is NSNull { return }
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: ["serverName", "allowInsecure", "alpn"], required: ["allowInsecure", "alpn"])
        try nullableString(object["serverName"], path: "\(path).serverName")
        guard object["allowInsecure"] is Bool else { throw CanonicalConfigError.invalidField(path: "\(path).allowInsecure") }
        try stringArray(object["alpn"]!, path: "\(path).alpn")
    }

    private static func nullableSecret(_ value: Any, path: String) throws {
        if value is NSNull { return }
        try secretReference(value, path: path)
    }

    private static func secretReference(_ value: Any, path: String) throws {
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: ["kind", "key"], required: ["kind", "key"])
        guard object["kind"] as? String == "keychain" else { throw CanonicalConfigError.invalidField(path: "\(path).kind") }
        let key = try stringValue(object["key"]!, path: "\(path).key")
        // The same rule the decoder and the schema apply, checked here so the
        // raw-JSON walk refuses a key even when nothing decodes it into a model.
        guard SecretReference.isValidKey(key) else {
            throw CanonicalConfigError.invalidField(path: "\(path).key")
        }
    }

    private static func dnsPolicy(_ value: Any, path: String) throws {
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: ["mode", "servers"], required: ["mode", "servers"])
        try enumeration(object["mode"]!, path: "\(path).mode", values: ["system", "tunnel", "custom"])
        try stringArray(object["servers"]!, path: "\(path).servers")
    }

    private static func privacyPolicy(_ value: Any, path: String) throws {
        let object = try object(value, path: path)
        try keys(object, path: path, allowed: [
            "telemetryEnabled", "trafficLogging", "domainHistory", "diagnosticsRetention", "redactServerAddresses", "redactCredentials"
        ], required: [
            "telemetryEnabled", "trafficLogging", "domainHistory", "diagnosticsRetention", "redactServerAddresses", "redactCredentials"
        ])
        try bool(object["telemetryEnabled"]!, path: "\(path).telemetryEnabled")
        try bool(object["trafficLogging"]!, path: "\(path).trafficLogging")
        try bool(object["domainHistory"]!, path: "\(path).domainHistory")
        try bool(object["redactServerAddresses"]!, path: "\(path).redactServerAddresses")
        try bool(object["redactCredentials"]!, path: "\(path).redactCredentials")
        try enumeration(object["diagnosticsRetention"]!, path: "\(path).diagnosticsRetention", values: ["memoryOnly", "userExport"])
    }

    private static func version(_ value: Any, path: String) throws {
        guard let number = value as? NSNumber,
              !isBoolean(number),
              number.doubleValue == 1,
              number.doubleValue == number.doubleValue.rounded() else {
            throw CanonicalConfigError.invalidField(path: path)
        }
    }

    private static func uuid(_ value: Any, path: String) throws {
        guard let string = value as? String, UUID(uuidString: string) != nil else {
            throw CanonicalConfigError.invalidField(path: path)
        }
    }

    private static func uuidArray(_ value: Any, path: String) throws {
        guard let array = value as? [Any] else { throw CanonicalConfigError.invalidField(path: path) }
        for element in array { try uuid(element, path: path) }
    }

    private static func stringArray(_ value: Any, path: String) throws {
        guard let array = value as? [Any] else { throw CanonicalConfigError.invalidField(path: path) }
        for element in array where !(element is String) { throw CanonicalConfigError.invalidField(path: path) }
    }

    private static func nullableString(_ value: Any?, path: String) throws {
        guard let value else { return }
        if value is NSNull { return }
        guard value is String else { throw CanonicalConfigError.invalidField(path: path) }
    }

    private static func nullableDate(_ value: Any?, path: String) throws {
        guard let value else { return }
        if value is NSNull { return }
        guard let string = value as? String, ISO8601DateFormatter().date(from: string) != nil else {
            throw CanonicalConfigError.invalidField(path: path)
        }
    }

    private static func string(_ value: Any, path: String) throws {
        _ = try stringValue(value, path: path)
    }

    private static func stringValue(_ value: Any, path: String) throws -> String {
        guard let string = value as? String else {
            throw CanonicalConfigError.invalidField(path: path)
        }
        return string
    }

    private static func enumeration(_ value: Any, path: String, values: [String]) throws {
        guard let string = value as? String, values.contains(string) else {
            throw CanonicalConfigError.invalidField(path: path)
        }
    }

    private static func port(_ value: Any, path: String) throws {
        guard let number = value as? NSNumber,
              !isBoolean(number),
              number.doubleValue == number.doubleValue.rounded() else {
            throw CanonicalConfigError.invalidField(path: path)
        }
    }

    private static func bool(_ value: Any, path: String) throws {
        guard value is Bool else {
            throw CanonicalConfigError.invalidField(path: path)
        }
    }

    private static func isBoolean(_ number: NSNumber) -> Bool {
        String(cString: number.objCType) == "c"
    }

    private static func array(_ value: Any, path: String, element: (Any) throws -> Void) throws {
        guard let values = value as? [Any] else { throw CanonicalConfigError.invalidField(path: path) }
        for value in values { try element(value) }
    }

    private static func keyed(_ value: Any, path: String) throws -> [String: Any] {
        try object(value, path: path)
    }

    private static func object(_ value: Any, path: String) throws -> [String: Any] {
        guard let object = value as? [String: Any] else {
            throw CanonicalConfigError.invalidField(path: path)
        }
        return object
    }

    private static func keys(
        _ object: [String: Any],
        path: String,
        allowed: Set<String>,
        required: Set<String>
    ) throws {
        if let unknown = object.keys.first(where: { !allowed.contains($0) }) {
            _ = unknown
            throw CanonicalConfigError.unknownField(path: path)
        }
        if let missing = required.sorted().first(where: { object[$0] == nil }) {
            throw CanonicalConfigError.invalidField(path: "\(path).\(missing)")
        }
    }
}
