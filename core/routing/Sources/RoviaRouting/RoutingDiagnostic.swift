import Foundation
import RoviaConfig

public enum RouteMatcherType: String, Codable, Sendable, Equatable {
    case domain
    case domainSuffix
    case ipCIDR
    case port
    case portRange
    case network

    public init(_ matcher: RouteMatcher) {
        switch matcher {
        case .domain: self = .domain
        case .domainSuffix: self = .domainSuffix
        case .ipCIDR: self = .ipCIDR
        case .port: self = .port
        case .portRange: self = .portRange
        case .network: self = .network
        }
    }
}

public enum RoutingMatcherReasonCode: String, Codable, Sendable, Equatable {
    case matcherMatched
    case matcherDidNotMatch
}

public enum RoutingRuleReasonCode: String, Codable, Sendable, Equatable {
    case ruleDisabled
    case noMatchers
    case noMatchingMatcher
    case firstMatchingRule
    case shadowedByEarlierMatch
}

public enum RoutingDiagnosticReasonCode: String, Codable, Sendable, Equatable {
    case firstMatchingRule
    case defaultAction
    case invalidInput
}

enum RoutingCodingSupport {
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

    static func rejectUnknownKeys(_ decoder: Decoder, allowed: Set<String>) throws {
        let container = try decoder.container(keyedBy: DynamicCodingKey.self)
        if let unknown = container.allKeys
            .sorted(by: { $0.stringValue < $1.stringValue })
            .first(where: { !allowed.contains($0.stringValue) }) {
            throw DecodingError.dataCorruptedError(
                forKey: unknown,
                in: container,
                debugDescription: "Unknown diagnostic field"
            )
        }
    }
}

private func safeMatcherReasonCode(_ value: String) -> String {
    RoutingMatcherReasonCode(rawValue: value)?.rawValue
        ?? RoutingMatcherReasonCode.matcherDidNotMatch.rawValue
}

private func safeRuleReasonCode(_ value: String) -> String {
    RoutingRuleReasonCode(rawValue: value)?.rawValue
        ?? RoutingRuleReasonCode.noMatchingMatcher.rawValue
}

private func safeDiagnosticReasonCode(_ value: String) -> String {
    RoutingDiagnosticReasonCode(rawValue: value)?.rawValue
        ?? RoutingDiagnosticReasonCode.invalidInput.rawValue
}

public struct RoutingInputSummary: Codable, Sendable, Equatable {
    public let hasHost: Bool
    public let hasIP: Bool
    public let hasPort: Bool
    public let hasNetwork: Bool

    public init(host: Bool, ip: Bool, port: Bool, network: Bool) {
        hasHost = host
        hasIP = ip
        hasPort = port
        hasNetwork = network
    }

    public init(_ input: RouteInput) {
        hasHost = input.host != nil
        hasIP = input.ip != nil
        hasPort = input.port != nil
        hasNetwork = input.network != nil
    }

    public init(from decoder: Decoder) throws {
        try RoutingCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["hasHost", "hasIP", "hasPort", "hasNetwork"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        hasHost = try container.decode(Bool.self, forKey: .hasHost)
        hasIP = try container.decode(Bool.self, forKey: .hasIP)
        hasPort = try container.decode(Bool.self, forKey: .hasPort)
        hasNetwork = try container.decode(Bool.self, forKey: .hasNetwork)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(hasHost, forKey: .hasHost)
        try container.encode(hasIP, forKey: .hasIP)
        try container.encode(hasPort, forKey: .hasPort)
        try container.encode(hasNetwork, forKey: .hasNetwork)
    }

    public var host: String { "redacted" }
    public var ip: String { "redacted" }
    public var port: Int? { nil }
    public var network: String? { nil }

    private enum CodingKeys: String, CodingKey {
        case hasHost
        case hasIP
        case hasPort
        case hasNetwork
    }
}

public struct RoutingMatcherDiagnostic: Codable, Sendable, Equatable {
    public let ruleID: UUID
    public let matcherIndex: Int
    public let matcherType: RouteMatcherType
    public let matched: Bool
    public let selected: Bool
    public let applied: Bool
    public let ruleEnabled: Bool
    public let reasonCode: String

    public init(
        ruleID: UUID,
        matcherIndex: Int,
        matcherType: RouteMatcherType,
        matched: Bool,
        selected: Bool,
        applied: Bool,
        ruleEnabled: Bool,
        reasonCode: String
    ) {
        self.ruleID = ruleID
        self.matcherIndex = matcherIndex
        self.matcherType = matcherType
        self.matched = matched
        self.selected = selected
        self.applied = applied
        self.ruleEnabled = ruleEnabled
        self.reasonCode = safeMatcherReasonCode(reasonCode)
    }

    public init(from decoder: Decoder) throws {
        try RoutingCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: [
                "ruleID", "matcherIndex", "matcherType", "matched",
                "selected", "applied", "ruleEnabled", "reasonCode"
            ]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ruleID = try container.decode(UUID.self, forKey: .ruleID)
        matcherIndex = try container.decode(Int.self, forKey: .matcherIndex)
        matcherType = try container.decode(RouteMatcherType.self, forKey: .matcherType)
        matched = try container.decode(Bool.self, forKey: .matched)
        selected = try container.decode(Bool.self, forKey: .selected)
        applied = try container.decode(Bool.self, forKey: .applied)
        ruleEnabled = try container.decode(Bool.self, forKey: .ruleEnabled)
        let value = try container.decode(String.self, forKey: .reasonCode)
        guard RoutingMatcherReasonCode(rawValue: value) != nil else {
            throw DecodingError.dataCorruptedError(
                forKey: .reasonCode,
                in: container,
                debugDescription: "Unknown routing matcher reason code"
            )
        }
        reasonCode = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ruleID, forKey: .ruleID)
        try container.encode(matcherIndex, forKey: .matcherIndex)
        try container.encode(matcherType, forKey: .matcherType)
        try container.encode(matched, forKey: .matched)
        try container.encode(selected, forKey: .selected)
        try container.encode(applied, forKey: .applied)
        try container.encode(ruleEnabled, forKey: .ruleEnabled)
        try container.encode(reasonCode, forKey: .reasonCode)
    }

    public var index: Int { matcherIndex }
    public var reason: String { reasonCode }
    public var reasonValue: RoutingMatcherReasonCode? { RoutingMatcherReasonCode(rawValue: reasonCode) }

    private enum CodingKeys: String, CodingKey {
        case ruleID
        case matcherIndex
        case matcherType
        case matched
        case selected
        case applied
        case ruleEnabled
        case reasonCode
    }
}

public struct RoutingRuleDiagnostic: Codable, Sendable, Equatable {
    public let ruleID: UUID
    public let enabled: Bool
    public let matched: Bool
    public let selected: Bool
    public let reasonCode: String
    public let matchers: [RoutingMatcherDiagnostic]

    public init(
        ruleID: UUID,
        enabled: Bool,
        matched: Bool,
        selected: Bool,
        reasonCode: String,
        matchers: [RoutingMatcherDiagnostic]
    ) {
        self.ruleID = ruleID
        self.enabled = enabled
        self.matched = matched
        self.selected = selected
        self.reasonCode = safeRuleReasonCode(reasonCode)
        self.matchers = matchers
    }

    public init(from decoder: Decoder) throws {
        try RoutingCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["ruleID", "enabled", "matched", "selected", "reasonCode", "matchers"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ruleID = try container.decode(UUID.self, forKey: .ruleID)
        enabled = try container.decode(Bool.self, forKey: .enabled)
        matched = try container.decode(Bool.self, forKey: .matched)
        selected = try container.decode(Bool.self, forKey: .selected)
        let value = try container.decode(String.self, forKey: .reasonCode)
        guard RoutingRuleReasonCode(rawValue: value) != nil else {
            throw DecodingError.dataCorruptedError(
                forKey: .reasonCode,
                in: container,
                debugDescription: "Unknown routing rule reason code"
            )
        }
        reasonCode = value
        matchers = try container.decode([RoutingMatcherDiagnostic].self, forKey: .matchers)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ruleID, forKey: .ruleID)
        try container.encode(enabled, forKey: .enabled)
        try container.encode(matched, forKey: .matched)
        try container.encode(selected, forKey: .selected)
        try container.encode(reasonCode, forKey: .reasonCode)
        try container.encode(matchers, forKey: .matchers)
    }

    public var reason: String { reasonCode }
    public var reasonValue: RoutingRuleReasonCode? { RoutingRuleReasonCode(rawValue: reasonCode) }
    public var applied: Bool { selected }

    private enum CodingKeys: String, CodingKey {
        case ruleID
        case enabled
        case matched
        case selected
        case reasonCode
        case matchers
    }
}

public struct RoutingDiagnostic: Codable, Sendable, Equatable {
    public let inputSummary: RoutingInputSummary
    public let rules: [RoutingRuleDiagnostic]
    public let matchers: [RoutingMatcherDiagnostic]
    public let finalDecision: RouteAction
    public let selectedGroup: UUID?
    public let selectedServer: UUID?
    public let reasonCode: String

    public init(
        inputSummary: RoutingInputSummary,
        rules: [RoutingRuleDiagnostic],
        matchers: [RoutingMatcherDiagnostic],
        finalDecision: RouteAction,
        selectedGroup: UUID? = nil,
        selectedServer: UUID? = nil,
        reasonCode: String
    ) {
        self.inputSummary = inputSummary
        self.rules = rules
        self.matchers = matchers
        self.finalDecision = finalDecision
        self.selectedGroup = selectedGroup
        self.selectedServer = selectedServer
        self.reasonCode = safeDiagnosticReasonCode(reasonCode)
    }

    public init(from decoder: Decoder) throws {
        try RoutingCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: [
                "inputSummary", "rules", "matchers", "finalDecision",
                "selectedGroup", "selectedServer", "reasonCode"
            ]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        inputSummary = try container.decode(RoutingInputSummary.self, forKey: .inputSummary)
        rules = try container.decode([RoutingRuleDiagnostic].self, forKey: .rules)
        matchers = try container.decode([RoutingMatcherDiagnostic].self, forKey: .matchers)
        finalDecision = try container.decode(RouteAction.self, forKey: .finalDecision)
        selectedGroup = try container.decode(UUID?.self, forKey: .selectedGroup)
        selectedServer = try container.decode(UUID?.self, forKey: .selectedServer)
        let value = try container.decode(String.self, forKey: .reasonCode)
        guard RoutingDiagnosticReasonCode(rawValue: value) != nil else {
            throw DecodingError.dataCorruptedError(
                forKey: .reasonCode,
                in: container,
                debugDescription: "Unknown routing diagnostic reason code"
            )
        }
        reasonCode = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(inputSummary, forKey: .inputSummary)
        try container.encode(rules, forKey: .rules)
        try container.encode(matchers, forKey: .matchers)
        try container.encode(finalDecision, forKey: .finalDecision)
        if let selectedGroup {
            try container.encode(selectedGroup, forKey: .selectedGroup)
        } else {
            try container.encodeNil(forKey: .selectedGroup)
        }
        if let selectedServer {
            try container.encode(selectedServer, forKey: .selectedServer)
        } else {
            try container.encodeNil(forKey: .selectedServer)
        }
        try container.encode(reasonCode, forKey: .reasonCode)
    }

    public var input: RoutingInputSummary { inputSummary }
    public var evaluations: [RoutingMatcherDiagnostic] { matchers }
    public var matcherEvaluations: [RoutingMatcherDiagnostic] { matchers }
    public var matcherDiagnostics: [RoutingMatcherDiagnostic] { matchers }
    public var ruleEvaluations: [RoutingRuleDiagnostic] { rules }
    public var finalAction: RouteAction { finalDecision }
    public var decision: RouteAction { finalDecision }
    public var reason: String { reasonCode }
    public var reasonValue: RoutingDiagnosticReasonCode? { RoutingDiagnosticReasonCode(rawValue: reasonCode) }
    public var selectedServerID: UUID? { selectedServer }

    private enum CodingKeys: String, CodingKey {
        case inputSummary
        case rules
        case matchers
        case finalDecision
        case selectedGroup
        case selectedServer
        case reasonCode
    }
}

public typealias MatcherDiagnostic = RoutingMatcherDiagnostic
public typealias RuleDiagnostic = RoutingRuleDiagnostic
public typealias MatcherReasonCode = RoutingMatcherReasonCode
public typealias RuleReasonCode = RoutingRuleReasonCode
public typealias DiagnosticReasonCode = RoutingDiagnosticReasonCode
