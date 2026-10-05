import Foundation
import XCTest
@testable import RoviaConfig

/// Coverage of `AppConfig.validationReport()`'s per-field semantic checks and
/// of the report/issue convenience API around it.
final class ConfigValidationReportTests: XCTestCase {
    private let serverID = UUID(uuidString: "00000000-0000-0000-0000-000000000101")!
    private let groupID = UUID(uuidString: "00000000-0000-0000-0000-000000000301")!
    private let subscriptionID = UUID(uuidString: "00000000-0000-0000-0000-000000000401")!
    private let ruleID = UUID(uuidString: "00000000-0000-0000-0000-000000000601")!

    // MARK: - report and issue conveniences

    func testIssueExposesTheJSONPathAlias() {
        let issue = ConfigValidationIssue(
            code: "invalidDNS",
            jsonPath: "dns.servers",
            severity: .warning,
            message: "Synthetic"
        )

        XCTAssertEqual(issue.path, "dns.servers")
        XCTAssertEqual(issue.jsonPath, "dns.servers")
        XCTAssertEqual(issue.severity, .warning)
    }

    func testReportAliasesAndWarningFiltering() {
        let warning = ConfigValidationIssue(code: "w", path: "p", severity: .warning, message: "m")
        let error = ConfigValidationIssue(code: "e", path: "p2", message: "m2")
        let report = ConfigValidationReport(issues: [warning, error])

        XCTAssertFalse(report.isValid)
        XCTAssertFalse(report.valid)
        XCTAssertTrue(report.hasErrors)
        XCTAssertEqual(report.warnings, [warning])
        XCTAssertEqual(report.errors, [error])

        let warningsOnly = ConfigValidationReport(issues: [warning])
        XCTAssertTrue(warningsOnly.isValid)
        XCTAssertTrue(warningsOnly.valid)
        XCTAssertFalse(warningsOnly.hasErrors)

        XCTAssertTrue(ConfigValidationReport().issues.isEmpty)
    }

    func testValidationErrorDescriptionCountsTheErrors() {
        let report = ConfigValidationReport(
            issues: [ConfigValidationIssue(code: "invalidDNS", path: "dns.servers", message: "m")]
        )
        let error = ConfigValidationError(report: report)

        XCTAssertEqual(error.description, "Configuration validation failed with 1 error(s).")
        XCTAssertEqual(error.errorDescription, error.description)
        XCTAssertEqual(error.issues, report.issues)
    }

    // MARK: - schema and privacy

    func testASchemaVersionMismatchIsReported() {
        let report = validConfig(schemaVersion: 2).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidSchemaVersion" && $0.path == "schemaVersion"
        })
    }

    func testAnUnsafePrivacyPolicyIsReported() throws {
        let unsafePrivacy = try JSONCoding.structuralDecoder().decode(
            PrivacyPolicy.self,
            from: Data(
                """
                {
                  "telemetryEnabled": true,
                  "trafficLogging": false,
                  "domainHistory": false,
                  "diagnosticsRetention": "memoryOnly",
                  "redactServerAddresses": true,
                  "redactCredentials": true
                }
                """.utf8
            )
        )
        let report = validConfig(privacy: unsafePrivacy).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "unsafePrivacyPolicy" && $0.path == "privacy"
        })
    }

    // MARK: - servers

    func testEmptyServerFieldsAreReported() {
        let unnamed = Server(
            id: UUID(),
            name: "  ",
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            transport: TransportOptions(kind: "tcp")
        )
        let hostless = Server(
            id: UUID(),
            name: "Synthetic",
            protocolKind: .vless,
            endpoint: Endpoint(host: " ", port: 443),
            transport: TransportOptions(kind: "tcp")
        )
        let kindless = Server(
            id: UUID(),
            name: "Synthetic",
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            transport: TransportOptions(kind: " ")
        )
        let report = validConfig(servers: [unnamed, hostless, kindless]).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidServer" && $0.path == "servers[0].name"
        })
        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidServer" && $0.path == "servers[1].endpoint.host"
        })
        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidServer" && $0.path == "servers[2].transport.kind"
        })
    }

    // MARK: - subscriptions

    func testDuplicateSubscriptionIDsAreReported() {
        let subscription = subscription(id: subscriptionID)
        let report = validConfig(subscriptions: [subscription, subscription]).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "duplicateSubscriptionID" && $0.path == "subscriptions[1].id"
        })
    }

    func testEmptySubscriptionNameIsReported() {
        let report = validConfig(subscriptions: [subscription(name: " ")]).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidSubscription" && $0.path == "subscriptions[0].name"
        })
    }

    func testDuplicateServerReferencesWithinASubscriptionAreReported() {
        let report = validConfig(
            subscriptions: [subscription(serverIDs: [serverID, serverID])]
        ).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidSubscription" && $0.path == "subscriptions[0].serverIDs[1]"
        })
        XCTAssertFalse(report.issues.contains { $0.code == "unknownServerReference" })
    }

    func testPastedSourceWithASecretReferenceIsReported() {
        let report = validConfig(
            subscriptions: [
                subscription(
                    source: SubscriptionSource(
                        kind: .pastedText,
                        displayValue: "pasted text",
                        secretReference: SecretReference(key: "subscription/synthetic")
                    )
                )
            ]
        ).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidSource" && $0.path == "subscriptions[0].source.secretReference"
        })
    }

    // MARK: - groups

    func testDuplicateGroupIDsAreReported() {
        let group = group(id: groupID)
        let report = validConfig(groups: [group, group]).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "duplicateGroupID" && $0.path == "groups[1].id"
        })
    }

    func testEmptyGroupNameAndMembersAreReported() {
        let report = validConfig(
            groups: [
                ServerGroup(id: UUID(), name: " ", mode: .manual, members: [serverID], selectionPolicy: .manual),
                ServerGroup(id: UUID(), name: "Empty", mode: .manual, members: [], selectionPolicy: .manual)
            ]
        ).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidGroup" && $0.path == "groups[0].name"
        })
        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidGroup" && $0.path == "groups[1].members"
        })
    }

    func testDuplicateMembersWithinAGroupAreReported() {
        let report = validConfig(groups: [group(members: [serverID, serverID])]).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidGroup" && $0.path == "groups[0].members[1]"
        })
        XCTAssertFalse(report.issues.contains { $0.code == "unknownServerReference" })
    }

    func testGroupModeAndSelectionPolicyMustAgree() {
        let mismatched = ServerGroup(
            id: UUID(),
            name: "Mismatched",
            mode: .manual,
            members: [serverID],
            selectionPolicy: .lowestLatency
        )
        let failover = ServerGroup(
            id: UUID(),
            name: "Failover",
            mode: .failover,
            members: [serverID],
            selectionPolicy: .failover
        )
        let report = validConfig(groups: [mismatched, failover]).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidGroup" && $0.path == "groups[0].selectionPolicy"
        })
        XCTAssertFalse(report.issues.contains { $0.path == "groups[1].selectionPolicy" })
    }

    // MARK: - routing

    func testDuplicateRouteRuleIDsAreReported() {
        let rule = RouteRule(id: ruleID, enabled: true, matchers: [.domain("example.com")], action: .direct)
        let report = validConfig(
            routing: RouteSet(rules: [rule, rule], defaultAction: .direct)
        ).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "duplicateRouteRuleID" && $0.path == "routing.rules[1].id"
        })
    }

    func testRouteRulesRequireAtLeastOneMatcher() {
        let rule = RouteRule(id: ruleID, enabled: true, matchers: [], action: .direct)
        let report = validConfig(
            routing: RouteSet(rules: [rule], defaultAction: .direct)
        ).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidRouteRule" && $0.path == "routing.rules[0].matchers"
        })
    }

    // MARK: - DNS

    func testCustomDNSRequiresAtLeastOneServer() {
        let report = validConfig(dns: DNSPolicy(mode: .custom, servers: [])).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidDNS" && $0.path == "dns.servers"
        })
    }

    func testEmptyDNSServerValuesAreReported() {
        let report = validConfig(dns: DNSPolicy(mode: .custom, servers: ["1.1.1.1", " "])).validationReport()

        XCTAssertTrue(report.issues.contains {
            $0.code == "invalidDNS" && $0.path == "dns.servers[1]"
        })
    }

    // MARK: - helpers

    private func validConfig(
        schemaVersion: Int = 1,
        subscriptions: [Subscription] = [],
        groups: [ServerGroup] = [],
        routing: RouteSet = RouteSet(rules: [], defaultAction: .direct),
        dns: DNSPolicy = DNSPolicy(mode: .system),
        privacy: PrivacyPolicy = PrivacyPolicy(),
        servers: [Server]? = nil
    ) -> AppConfig {
        AppConfig(
            schemaVersion: schemaVersion,
            subscriptions: subscriptions,
            groups: groups,
            routing: routing,
            dns: dns,
            privacy: privacy,
            servers: servers ?? [server()]
        )
    }

    private func server(id: UUID? = nil) -> Server {
        Server(
            id: id ?? serverID,
            name: "Synthetic Server",
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            transport: TransportOptions(kind: "tcp")
        )
    }

    private func group(
        id: UUID = UUID(),
        members: [UUID] = [UUID(uuidString: "00000000-0000-0000-0000-000000000101")!],
        mode: GroupMode = .manual,
        selectionPolicy: SelectionPolicy = .manual
    ) -> ServerGroup {
        ServerGroup(id: id, name: "Group", mode: mode, members: members, selectionPolicy: selectionPolicy)
    }

    private func subscription(
        id: UUID = UUID(),
        name: String = "Subscription",
        source: SubscriptionSource = SubscriptionSource(kind: .pastedText, displayValue: "pasted text"),
        serverIDs: [UUID] = []
    ) -> Subscription {
        Subscription(
            id: id,
            name: name,
            source: source,
            serverIDs: serverIDs,
            refreshPolicy: RefreshPolicy(mode: .manual)
        )
    }
}
