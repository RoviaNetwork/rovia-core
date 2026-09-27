import Foundation
import XCTest
@testable import RoviaConfig
@testable import RoviaRouting

final class RoutingDiagnosticTests: XCTestCase {
    func testExplainEvaluatesEveryMatcherAndPreservesFirstMatchingRule() throws {
        let firstGroupID = UUID(uuidString: "00000000-0000-0000-0000-000000000401")!
        let firstServerID = UUID(uuidString: "00000000-0000-0000-0000-000000000402")!
        let firstRuleID = UUID(uuidString: "00000000-0000-0000-0000-000000000403")!
        let secondRuleID = UUID(uuidString: "00000000-0000-0000-0000-000000000404")!
        let routeSet = RouteSet(
            rules: [
                RouteRule(
                    id: firstRuleID,
                    enabled: true,
                    matchers: [.domain("first.example"), .port(443), .network("tcp")],
                    action: .group(firstGroupID)
                ),
                RouteRule(
                    id: secondRuleID,
                    enabled: true,
                    matchers: [.domain("first.example"), .ipCIDR("10.0.0.0/8"), .port(80)],
                    action: .block
                )
            ],
            defaultAction: .direct
        )

        let diagnostic = try RouteEvaluator().explain(
            RouteInput(host: "first.example", ip: "10.2.3.4", port: 443, network: "TCP"),
            using: routeSet,
            context: RouteEvaluationContext(
                knownGroupIDs: [firstGroupID],
                selectedServers: [firstGroupID: firstServerID]
            )
        )

        XCTAssertEqual(diagnostic.rules.count, 2)
        XCTAssertEqual(diagnostic.rules[0].matchers.count, 3)
        XCTAssertEqual(diagnostic.rules[1].matchers.count, 3)
        XCTAssertEqual(diagnostic.matchers.count, 6)
        XCTAssertEqual(diagnostic.matchers.map(\.reasonCode), [
            "matcherMatched", "matcherMatched", "matcherMatched",
            "matcherMatched", "matcherMatched", "matcherDidNotMatch"
        ])
        XCTAssertEqual(diagnostic.rules[0].reasonCode, "firstMatchingRule")
        XCTAssertTrue(diagnostic.rules[0].matchers[0].applied)
        XCTAssertFalse(diagnostic.rules[0].matchers[1].applied)
        XCTAssertFalse(diagnostic.rules[0].matchers[2].applied)
        XCTAssertEqual(diagnostic.rules[1].reasonCode, "shadowedByEarlierMatch")
        XCTAssertTrue(diagnostic.rules[0].selected)
        XCTAssertFalse(diagnostic.rules[1].selected)
        XCTAssertEqual(diagnostic.finalDecision, .group(firstGroupID))
        XCTAssertEqual(diagnostic.selectedGroup, firstGroupID)
        XCTAssertEqual(diagnostic.selectedServer, firstServerID)
        XCTAssertEqual(diagnostic.reasonCode, "firstMatchingRule")
    }

    func testExplainRecordsAllSupportedMatcherTypes() throws {
        let routeSet = RouteSet(
            rules: [
                RouteRule(
                    id: UUID(),
                    enabled: true,
                    matchers: [
                        .domain("sub.example.com"),
                        .domainSuffix("example.com"),
                        .ipCIDR("10.0.0.0/8"),
                        .port(443),
                        .portRange(lower: 80, upper: 443),
                        .network("TCP")
                    ],
                    action: .block
                )
            ],
            defaultAction: .direct
        )

        let diagnostic = try RouteEvaluator().explain(
            RouteInput(host: "sub.example.com", ip: "10.1.2.3", port: 443, network: "TCP"),
            using: routeSet,
            context: RouteEvaluationContext()
        )

        XCTAssertEqual(diagnostic.matchers.count, 6)
        XCTAssertTrue(diagnostic.matchers.allSatisfy(\.matched))
        XCTAssertEqual(diagnostic.matchers.map(\.matcherType), [
            .domain, .domainSuffix, .ipCIDR, .port, .portRange, .network
        ])
        XCTAssertEqual(diagnostic.matchers.filter(\.applied).count, 1)
    }

    func testExplainRedactsDestinationsMatcherValuesAndUserTextByDefault() throws {
        let groupID = UUID(uuidString: "00000000-0000-0000-0000-000000000411")!
        let serverID = UUID(uuidString: "00000000-0000-0000-0000-000000000412")!
        let routeSet = RouteSet(
            rules: [
                RouteRule(
                    id: UUID(),
                    enabled: true,
                    matchers: [
                        .domain("host-matcher-canary.example"),
                        .ipCIDR("203.0.113.0/24"),
                        .network("network-matcher-canary")
                    ],
                    action: .group(groupID),
                    note: "rule-note-canary"
                )
            ],
            defaultAction: .direct
        )
        let input = RouteInput(
            host: "host-input-canary.example",
            ip: "203.0.113.42",
            port: 443,
            network: "network-input-canary"
        )

        let diagnostic = try RouteEvaluator().explain(
            input,
            using: routeSet,
            context: RouteEvaluationContext(
                knownGroupIDs: [groupID],
                selectedServers: [groupID: serverID]
            )
        )
        let data = try JSONCoding.encoder().encode(diagnostic)
        let encoded = String(decoding: data, as: UTF8.self)
        let reflected = String(describing: diagnostic)
        let decoded = try JSONCoding.decoder().decode(RoutingDiagnostic.self, from: data)

        XCTAssertEqual(decoded, diagnostic)
        XCTAssertTrue(encoded.contains("\"selectedGroup\":\"\(groupID)\""))
        XCTAssertTrue(encoded.contains("\"selectedServer\":\"\(serverID)\""))

        let canaries = [
            "host-matcher-canary.example",
            "203.0.113.0/24",
            "network-matcher-canary",
            "host-input-canary.example",
            "203.0.113.42",
            "network-input-canary",
            "rule-note-canary"
        ]
        for (index, canary) in canaries.enumerated() {
            XCTAssertFalse(encoded.contains(canary), "redaction case \(index)")
            XCTAssertFalse(reflected.contains(canary), "redaction case \(index)")
        }
        XCTAssertTrue(diagnostic.inputSummary.hasHost)
        XCTAssertTrue(diagnostic.inputSummary.hasIP)
        XCTAssertTrue(diagnostic.inputSummary.hasPort)
        XCTAssertTrue(diagnostic.inputSummary.hasNetwork)
        XCTAssertEqual(diagnostic.matchers.map(\.matcherType), [
            .domain, .ipCIDR, .network
        ])
    }

    func testExplainRecordsDisabledAndNonMatchingMatchersWithoutLeakingTheirValues() throws {
        let routeSet = RouteSet(
            rules: [
                RouteRule(
                    id: UUID(),
                    enabled: false,
                    matchers: [.domain("example.com"), .port(443)],
                    action: .block
                ),
                RouteRule(
                    id: UUID(),
                    enabled: true,
                    matchers: [.domain("unmatched-canary.example"), .port(80)],
                    action: .direct
                )
            ],
            defaultAction: .direct
        )

        let diagnostic = try RouteEvaluator().explain(
            RouteInput(host: "example.com", ip: nil, port: 443, network: "tcp"),
            using: routeSet,
            context: RouteEvaluationContext()
        )
        let encoded = String(decoding: try JSONCoding.encoder().encode(diagnostic), as: UTF8.self)

        XCTAssertEqual(diagnostic.matchers.count, 4)
        XCTAssertEqual(diagnostic.rules[0].reasonCode, "ruleDisabled")
        XCTAssertTrue(diagnostic.rules[0].matchers[0].matched)
        XCTAssertTrue(diagnostic.rules[0].matchers[1].matched)
        XCTAssertEqual(diagnostic.rules[1].reasonCode, "noMatchingMatcher")
        XCTAssertEqual(diagnostic.rules[1].matchers[0].reasonCode, "matcherDidNotMatch")
        XCTAssertEqual(diagnostic.rules[1].matchers[1].reasonCode, "matcherDidNotMatch")
        XCTAssertFalse(encoded.contains("disabled-canary.example"))
        XCTAssertFalse(encoded.contains("unmatched-canary.example"))
    }

    func testDiagnosticStringInitializersMapUnsafeReasonsToRoleSafeCodes() throws {
        let id = UUID(uuidString: "00000000-0000-0000-0000-000000000701")!
        let unsafeValues = [
            "matcher-canary",
            "rule-canary",
            "diagnostic-canary",
            "decision-canary"
        ]
        let matcher = RoutingMatcherDiagnostic(
            ruleID: id,
            matcherIndex: 0,
            matcherType: .domain,
            matched: false,
            selected: false,
            applied: false,
            ruleEnabled: true,
            reasonCode: unsafeValues[0]
        )
        let rule = RoutingRuleDiagnostic(
            ruleID: id,
            enabled: true,
            matched: false,
            selected: false,
            reasonCode: unsafeValues[1],
            matchers: [matcher]
        )
        let diagnostic = RoutingDiagnostic(
            inputSummary: RoutingInputSummary(host: false, ip: false, port: false, network: false),
            rules: [rule],
            matchers: [matcher],
            finalDecision: .direct,
            reasonCode: unsafeValues[2]
        )
        let decision = GroupSelectionDecision(
            groupID: id,
            policy: .failover,
            selectedServerID: nil,
            reasonCode: unsafeValues[3]
        )

        XCTAssertEqual(matcher.reasonCode, "matcherDidNotMatch")
        XCTAssertEqual(rule.reasonCode, "noMatchingMatcher")
        XCTAssertEqual(diagnostic.reasonCode, "invalidInput")
        XCTAssertEqual(decision.reasonCode, "noHealthyCandidate")

        let crossRoleMatcher = RoutingMatcherDiagnostic(
            ruleID: id,
            matcherIndex: 0,
            matcherType: .domain,
            matched: true,
            selected: true,
            applied: true,
            ruleEnabled: true,
            reasonCode: "firstMatchingRule"
        )
        let crossRoleRule = RoutingRuleDiagnostic(
            ruleID: id,
            enabled: true,
            matched: true,
            selected: true,
            reasonCode: "matcherMatched",
            matchers: [crossRoleMatcher]
        )
        let crossRoleDiagnostic = RoutingDiagnostic(
            inputSummary: RoutingInputSummary(host: false, ip: false, port: false, network: false),
            rules: [crossRoleRule],
            matchers: [crossRoleMatcher],
            finalDecision: .direct,
            reasonCode: "matcherDidNotMatch"
        )

        XCTAssertEqual(crossRoleMatcher.reasonCode, "matcherDidNotMatch")
        XCTAssertEqual(crossRoleRule.reasonCode, "noMatchingMatcher")
        XCTAssertEqual(crossRoleDiagnostic.reasonCode, "invalidInput")

        let encoded = try JSONCoding.encoder().encode(diagnostic)
        let reflected = String(describing: diagnostic)
        for (index, value) in unsafeValues.enumerated() {
            XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains(value), "case \(index)")
            XCTAssertFalse(reflected.contains(value), "case \(index)")
        }
    }

    func testMatcherAndRuleDecodersRejectUnknownFieldsAndCrossRoleReasons() throws {
        let matcherID = "00000000-0000-0000-0000-000000000711"
        let matcherFields = "\"ruleID\":\"\(matcherID)\",\"matcherIndex\":0,\"matcherType\":\"domain\",\"matched\":true,\"selected\":true,\"applied\":true,\"ruleEnabled\":true"
        let matcherUnknown = Data("{\(matcherFields),\"reasonCode\":\"matcherMatched\",\"rawInput\":\"matcher-field-canary\"}".utf8)
        let matcherCrossRole = Data("{\(matcherFields),\"reasonCode\":\"firstMatchingRule\"}".utf8)
        for (index, data) in [matcherUnknown, matcherCrossRole].enumerated() {
            XCTAssertThrowsError(try JSONCoding.decoder().decode(RoutingMatcherDiagnostic.self, from: data)) { error in
                XCTAssertFalse(String(describing: error).contains("matcher-field-canary"), "case \(index)")
            }
        }

        let ruleFields = "\"ruleID\":\"\(matcherID)\",\"enabled\":true,\"matched\":true,\"selected\":true"
        let ruleUnknown = Data("{\(ruleFields),\"reasonCode\":\"firstMatchingRule\",\"matchers\":[],\"rawInput\":\"rule-field-canary\"}".utf8)
        let ruleCrossRole = Data("{\(ruleFields),\"reasonCode\":\"matcherMatched\",\"matchers\":[]}".utf8)
        for (index, data) in [ruleUnknown, ruleCrossRole].enumerated() {
            XCTAssertThrowsError(try JSONCoding.decoder().decode(RoutingRuleDiagnostic.self, from: data)) { error in
                XCTAssertFalse(String(describing: error).contains("rule-field-canary"), "case \(index)")
            }
        }
    }

    func testSummaryAndDiagnosticDecodersRejectUnknownFieldsAndCrossRoleReasons() throws {
        let summaryUnknown = Data("{\"hasHost\":false,\"hasIP\":false,\"hasPort\":false,\"hasNetwork\":false,\"rawInput\":\"summary-field-canary\"}".utf8)
        XCTAssertThrowsError(try JSONCoding.decoder().decode(RoutingInputSummary.self, from: summaryUnknown)) { error in
            XCTAssertFalse(String(describing: error).contains("summary-field-canary"))
        }

        let diagnosticFields = "\"inputSummary\":{\"hasHost\":false,\"hasIP\":false,\"hasPort\":false,\"hasNetwork\":false},\"rules\":[],\"matchers\":[],\"finalDecision\":{\"type\":\"direct\"},\"selectedGroup\":null,\"selectedServer\":null"
        let diagnosticUnknown = Data("{\(diagnosticFields),\"reasonCode\":\"defaultAction\",\"rawInput\":\"diagnostic-field-canary\"}".utf8)
        let diagnosticCrossRole = Data("{\(diagnosticFields),\"reasonCode\":\"matcherDidNotMatch\"}".utf8)
        for (index, data) in [diagnosticUnknown, diagnosticCrossRole].enumerated() {
            XCTAssertThrowsError(try JSONCoding.decoder().decode(RoutingDiagnostic.self, from: data)) { error in
                XCTAssertFalse(String(describing: error).contains("diagnostic-field-canary"), "case \(index)")
            }
        }
    }

    func testGroupSelectionDecisionDecoderRejectsUnknownFieldsAndCrossRoleReasons() throws {
        let base = "\"groupID\":\"00000000-0000-0000-0000-000000000731\",\"policy\":\"failover\",\"selectedServerID\":null"
        let unknown = Data("{\(base),\"reasonCode\":\"noHealthyCandidate\",\"rawInput\":\"decision-field-canary\"}".utf8)
        let crossRole = Data("{\(base),\"reasonCode\":\"matcherDidNotMatch\"}".utf8)
        for (index, data) in [unknown, crossRole].enumerated() {
            XCTAssertThrowsError(try JSONCoding.decoder().decode(GroupSelectionDecision.self, from: data)) { error in
                XCTAssertFalse(String(describing: error).contains("decision-field-canary"), "case \(index)")
            }
        }
    }

    func testDiagnosticAndSelectionDecisionRequireNullableSelectionKeys() {
        let diagnosticWithoutGroup = Data("{\"inputSummary\":{\"hasHost\":false,\"hasIP\":false,\"hasPort\":false,\"hasNetwork\":false},\"rules\":[],\"matchers\":[],\"finalDecision\":{\"type\":\"direct\"},\"selectedServer\":null,\"reasonCode\":\"defaultAction\"}".utf8)
        let diagnosticWithoutServer = Data("{\"inputSummary\":{\"hasHost\":false,\"hasIP\":false,\"hasPort\":false,\"hasNetwork\":false},\"rules\":[],\"matchers\":[],\"finalDecision\":{\"type\":\"direct\"},\"selectedGroup\":null,\"reasonCode\":\"defaultAction\"}".utf8)
        let decisionWithoutServer = Data("{\"groupID\":\"00000000-0000-0000-0000-000000000741\",\"policy\":\"failover\",\"reasonCode\":\"noHealthyCandidate\"}".utf8)

        for (index, data) in [diagnosticWithoutGroup, diagnosticWithoutServer].enumerated() {
            XCTAssertThrowsError(try JSONCoding.decoder().decode(RoutingDiagnostic.self, from: data), "case \(index)")
        }
        XCTAssertThrowsError(try JSONCoding.decoder().decode(GroupSelectionDecision.self, from: decisionWithoutServer))
    }

    func testExplainUsesDefaultActionReasonWhenNoRuleMatches() throws {
        let diagnostic = try RouteEvaluator().explain(
            RouteInput(host: nil, ip: nil, port: nil, network: nil),
            using: RouteSet(rules: [], defaultAction: .direct),
            context: RouteEvaluationContext()
        )

        let data = try JSONCoding.encoder().encode(diagnostic)
        let encoded = String(decoding: data, as: UTF8.self)

        XCTAssertEqual(diagnostic.reasonCode, "defaultAction")
        XCTAssertEqual(diagnostic.finalDecision, .direct)
        XCTAssertTrue(diagnostic.rules.isEmpty)
        XCTAssertTrue(diagnostic.matchers.isEmpty)
        XCTAssertTrue(encoded.contains("\"selectedGroup\":null"))
        XCTAssertTrue(encoded.contains("\"selectedServer\":null"))
    }
}
