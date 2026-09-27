import Foundation
import RoviaConfig

public enum RouteEvaluationError: Error, Equatable, Sendable, CustomStringConvertible, LocalizedError {
    case invalidPort
    case invalidCIDR
    case invalidIPAddress
    case invalidMatcher
    case unknownGroup

    public var description: String {
        switch self {
        case .invalidPort: "The route port is invalid."
        case .invalidCIDR: "The route CIDR is invalid."
        case .invalidIPAddress: "The route IP address is invalid."
        case .invalidMatcher: "The route matcher is invalid."
        case .unknownGroup: "The route group is unknown."
        }
    }

    public var errorDescription: String? { description }
}

public enum RouteMatcherValidation {
    public static func validate(_ matcher: RouteMatcher) throws {
        do {
            try CanonicalRouteMatcherValidator.validate(matcher)
        } catch let error as CanonicalRouteValidationError {
            switch error {
            case .invalidPort:
                throw RouteEvaluationError.invalidPort
            case .invalidCIDR:
                throw RouteEvaluationError.invalidCIDR
            case .invalidIPAddress:
                throw RouteEvaluationError.invalidIPAddress
            case .invalidMatcher:
                throw RouteEvaluationError.invalidMatcher
            }
        }
    }

    public static func validate(_ matchers: [RouteMatcher]) throws {
        for matcher in matchers {
            try validate(matcher)
        }
    }
}

public typealias RouteValidation = RouteMatcherValidation
public typealias RouteMatcherValidator = RouteMatcherValidation

public struct RouteEvaluationContext: Sendable, Equatable {
    public let knownGroupIDs: Set<UUID>
    public let selectedServers: [UUID: UUID]

    public init(
        knownGroupIDs: Set<UUID> = [],
        selectedServers: [UUID: UUID] = [:]
    ) {
        self.knownGroupIDs = knownGroupIDs
        self.selectedServers = selectedServers
    }
}

public struct RouteEvaluator: Sendable {
    public init() {}

    public func evaluate(
        _ input: RouteInput,
        using routeSet: RouteSet,
        context: RouteEvaluationContext
    ) throws -> RoutingDecisionTrace {
        try validate(routeSet: routeSet, context: context)
        let normalizedInput = try normalize(input)
        var evaluations: [RuleEvaluation] = []
        var finalDecision = routeSet.defaultAction
        var selectedRule = false

        for rule in routeSet.rules {
            guard rule.enabled else {
                evaluations.append(
                    RuleEvaluation(
                        ruleID: rule.id,
                        matched: false,
                        reason: "disabled"
                    )
                )
                continue
            }

            var matchedMatcher: RouteMatcher?
            for matcher in rule.matchers {
                if try matches(matcher, input: normalizedInput) {
                    matchedMatcher = matcher
                    break
                }
            }

            let matched = matchedMatcher != nil
            let reason = matched ? "matched \(matcherName(matchedMatcher!))" : "no matching matcher"
            evaluations.append(
                RuleEvaluation(
                    ruleID: rule.id,
                    matched: matched,
                    reason: reason,
                    matchedMatcher: matchedMatcher
                )
            )

            if matched && !selectedRule {
                finalDecision = rule.action
                selectedRule = true
            }
        }

        let selectedGroup: UUID?
        let selectedServer: UUID?
        if case let .group(id) = finalDecision {
            selectedGroup = id
            selectedServer = context.selectedServers[id]
        } else {
            selectedGroup = nil
            selectedServer = nil
        }

        return RoutingDecisionTrace(
            input: input,
            normalizedInput: normalizedInput,
            evaluations: evaluations,
            finalDecision: finalDecision,
            selectedGroup: selectedGroup,
            selectedServer: selectedServer
        )
    }

    public func explain(
        _ input: RouteInput,
        using routeSet: RouteSet,
        context: RouteEvaluationContext = RouteEvaluationContext()
    ) throws -> RoutingDiagnostic {
        try validate(routeSet: routeSet, context: context)
        let normalizedInput = try normalize(input)
        var ruleDiagnostics: [RoutingRuleDiagnostic] = []
        var matcherDiagnostics: [RoutingMatcherDiagnostic] = []
        var finalDecision = routeSet.defaultAction
        var selectedRule = false
        var finalReasonCode = RoutingDiagnosticReasonCode.defaultAction.rawValue

        for rule in routeSet.rules {
            var diagnostics: [RoutingMatcherDiagnostic] = []
            for (index, matcher) in rule.matchers.enumerated() {
                let matched = try matches(matcher, input: normalizedInput)
                diagnostics.append(
                    RoutingMatcherDiagnostic(
                        ruleID: rule.id,
                        matcherIndex: index,
                        matcherType: RouteMatcherType(matcher),
                        matched: matched,
                        selected: false,
                        applied: false,
                        ruleEnabled: rule.enabled,
                        reasonCode: matched
                            ? RoutingMatcherReasonCode.matcherMatched.rawValue
                            : RoutingMatcherReasonCode.matcherDidNotMatch.rawValue
                    )
                )
            }

            let matched = rule.enabled && diagnostics.contains(where: { $0.matched })
            let isSelected = matched && !selectedRule
            let reasonCode: String
            if !rule.enabled {
                reasonCode = RoutingRuleReasonCode.ruleDisabled.rawValue
            } else if rule.matchers.isEmpty {
                reasonCode = RoutingRuleReasonCode.noMatchers.rawValue
            } else if isSelected {
                reasonCode = RoutingRuleReasonCode.firstMatchingRule.rawValue
            } else if matched {
                reasonCode = RoutingRuleReasonCode.shadowedByEarlierMatch.rawValue
            } else {
                reasonCode = RoutingRuleReasonCode.noMatchingMatcher.rawValue
            }

            let firstMatchedIndex = diagnostics.firstIndex(where: { $0.matched })
            let selectedDiagnostics = diagnostics.map { diagnostic in
                let isFirstMatch = diagnostic.matcherIndex == firstMatchedIndex
                return RoutingMatcherDiagnostic(
                    ruleID: diagnostic.ruleID,
                    matcherIndex: diagnostic.matcherIndex,
                    matcherType: diagnostic.matcherType,
                    matched: diagnostic.matched,
                    selected: isSelected && isFirstMatch,
                    applied: isSelected && isFirstMatch,
                    ruleEnabled: diagnostic.ruleEnabled,
                    reasonCode: diagnostic.reasonCode
                )
            }
            ruleDiagnostics.append(
                RoutingRuleDiagnostic(
                    ruleID: rule.id,
                    enabled: rule.enabled,
                    matched: matched,
                    selected: isSelected,
                    reasonCode: reasonCode,
                    matchers: selectedDiagnostics
                )
            )
            matcherDiagnostics.append(contentsOf: selectedDiagnostics)

            if isSelected {
                finalDecision = rule.action
                selectedRule = true
                finalReasonCode = RoutingDiagnosticReasonCode(rawValue: reasonCode)?.rawValue
                    ?? RoutingDiagnosticReasonCode.invalidInput.rawValue
            }
        }

        let selectedGroup: UUID?
        let selectedServer: UUID?
        if case let .group(id) = finalDecision {
            selectedGroup = id
            selectedServer = context.selectedServers[id]
        } else {
            selectedGroup = nil
            selectedServer = nil
        }

        return RoutingDiagnostic(
            inputSummary: RoutingInputSummary(input),
            rules: ruleDiagnostics,
            matchers: matcherDiagnostics,
            finalDecision: finalDecision,
            selectedGroup: selectedGroup,
            selectedServer: selectedServer,
            reasonCode: finalReasonCode
        )
    }

    public func explain(
        _ input: RouteInput,
        routeSet: RouteSet,
        context: RouteEvaluationContext = RouteEvaluationContext()
    ) throws -> RoutingDiagnostic {
        try explain(input, using: routeSet, context: context)
    }

    private func validate(routeSet: RouteSet, context: RouteEvaluationContext) throws {
        try validate(action: routeSet.defaultAction, context: context)
        for rule in routeSet.rules {
            try validate(action: rule.action, context: context)
            for matcher in rule.matchers {
                try validate(matcher: matcher)
            }
        }
    }

    private func validate(action: RouteAction, context: RouteEvaluationContext) throws {
        if case let .group(id) = action, !context.knownGroupIDs.contains(id) {
            throw RouteEvaluationError.unknownGroup
        }
    }

    private func validate(matcher: RouteMatcher) throws {
        try RouteMatcherValidation.validate(matcher)
    }

    private func normalize(_ input: RouteInput) throws -> RouteInput {
        if let port = input.port, !(1...65_535).contains(port) {
            throw RouteEvaluationError.invalidPort
        }

        let host = input.host.flatMap(CanonicalRouteMatcherValidator.normalizeDomain)
        let ip = input.ip.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        if let ip, CanonicalRouteMatcherValidator.normalizeIPAddress(ip) == nil {
            throw RouteEvaluationError.invalidIPAddress
        }

        let network = input.network.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }

        return RouteInput(host: host, ip: ip, port: input.port, network: network)
    }

    private func matches(_ matcher: RouteMatcher, input: RouteInput) throws -> Bool {
        switch matcher {
        case let .domain(value):
            // Both sides have to be present. `host` is an Optional because a
            // degenerate input normalises to nothing, and comparing two
            // Optionals makes `nil == nil` true — so a degenerate matcher
            // matched a degenerate host, and no rule described either.
            guard let host = input.host,
                  let expected = CanonicalRouteMatcherValidator.normalizeDomain(value) else {
                return false
            }
            return host == expected
        case let .domainSuffix(value):
            guard let host = input.host,
                  let suffix = CanonicalRouteMatcherValidator.normalizeDomain(value),
                  !suffix.isEmpty else {
                return false
            }
            return host == suffix || host.hasSuffix("." + suffix)
        case let .ipCIDR(value):
            guard let ip = input.ip else { return false }
            return try CanonicalRouteMatcherValidator.cidr(value, contains: ip)
        case let .port(value):
            guard let port = input.port else { return false }
            return port == value
        case let .portRange(lower, upper):
            guard let port = input.port else { return false }
            return lower...upper ~= port
        case let .network(value):
            guard let network = input.network else { return false }
            return network == value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
    }

    private func matcherName(_ matcher: RouteMatcher) -> String {
        switch matcher {
        case .domain: "domain"
        case .domainSuffix: "domainSuffix"
        case .ipCIDR: "ipCIDR"
        case .port: "port"
        case .portRange: "portRange"
        case .network: "network"
        }
    }
}
