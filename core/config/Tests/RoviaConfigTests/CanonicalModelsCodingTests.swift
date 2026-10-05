import Foundation
import XCTest
@testable import RoviaConfig

/// Coverage of the custom `Codable` conformances in `CanonicalModels.swift`:
/// per-branch decoders, encoding guards, memberwise conveniences, and the
/// `validateForPersistence` throws that mirror the validation report.
final class CanonicalModelsCodingTests: XCTestCase {
    private let serverID = UUID(uuidString: "00000000-0000-0000-0000-000000000101")!
    private let groupID = UUID(uuidString: "00000000-0000-0000-0000-000000000301")!

    // MARK: - strict coding entry points

    func testStrictCoderRoundTripsLikeTheDefaultCoder() throws {
        let policy = RefreshPolicy(mode: .interval, interval: 60)

        let strictData = try JSONCoding.strictEncoder().encode(policy)
        let defaultData = try JSONCoding.encoder().encode(policy)

        XCTAssertEqual(strictData, defaultData)
        XCTAssertEqual(
            try JSONCoding.strictDecoder().decode(RefreshPolicy.self, from: strictData),
            policy
        )
    }

    // MARK: - TLS options

    func testTLSOptionsMemberwiseInitAndRoundTrip() throws {
        let tls = TLSOptions(serverName: "synthetic.example", allowInsecure: true, alpn: ["h2"])

        let data = try JSONCoding.encoder().encode(tls)
        let decoded = try JSONCoding.decoder().decode(TLSOptions.self, from: data)

        XCTAssertEqual(decoded, tls)
        XCTAssertEqual(decoded.serverName, "synthetic.example")
        XCTAssertTrue(decoded.allowInsecure)
        XCTAssertEqual(decoded.alpn, ["h2"])
    }

    // MARK: - server encoding with present credential and TLS

    func testServerEncodingKeepsPresentCredentialAndTLS() throws {
        let server = Server(
            id: serverID,
            name: "Synthetic Server",
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            credential: SecretReference(key: "server/synthetic"),
            transport: TransportOptions(kind: "tcp"),
            tls: TLSOptions(serverName: "synthetic.example", allowInsecure: false, alpn: ["h2"]),
            tags: ["synthetic"]
        )

        let json = String(decoding: try JSONCoding.encoder().encode(server), as: UTF8.self)

        XCTAssertTrue(json.contains("\"credential\":{\"key\":\"server/synthetic\",\"kind\":\"keychain\"}"))
        XCTAssertTrue(json.contains("\"serverName\":\"synthetic.example\""))
        XCTAssertFalse(json.contains("\"credential\":null"))
        XCTAssertFalse(json.contains("\"tls\":null"))
    }

    // MARK: - subscription source guards

    func testPastedAndFileSourceDecodingRejectsRawProxyLinks() {
        for kind in ["pastedText", "file"] {
            let data = Data(
                "{\"kind\":\"\(kind)\",\"displayValue\":\"vless://raw-share-link\",\"secretReference\":null}".utf8
            )

            XCTAssertThrowsError(
                try JSONCoding.decoder().decode(SubscriptionSource.self, from: data),
                kind
            ) { error in
                XCTAssertFalse(String(describing: error).contains("raw-share-link"), kind)
            }
        }
    }

    func testPastedSourceDecodingRejectsASecretReference() {
        let data = Data(
            "{\"kind\":\"pastedText\",\"displayValue\":\"pasted text\",\"secretReference\":{\"kind\":\"keychain\",\"key\":\"subscription/synthetic\"}}".utf8
        )

        XCTAssertThrowsError(try JSONCoding.decoder().decode(SubscriptionSource.self, from: data))
    }

    func testPastedSourceEncodingRejectsASecretReference() {
        let source = SubscriptionSource(
            kind: .pastedText,
            displayValue: "pasted text",
            secretReference: SecretReference(key: "subscription/synthetic")
        )

        XCTAssertThrowsError(try JSONCoding.encoder().encode(source))
    }

    func testSourceEncodingRoundTripsSanitizedValues() throws {
        let pasted = SubscriptionSource(kind: .pastedText, displayValue: "pasted text")
        let url = SubscriptionSource(
            kind: .url,
            displayValue: "https://subscriptions.example/feed",
            secretReference: SecretReference(key: "subscription/synthetic")
        )

        let pastedData = try JSONCoding.encoder().encode(pasted)
        let urlData = try JSONCoding.encoder().encode(url)
        let urlJSON = String(decoding: urlData, as: UTF8.self)

        XCTAssertEqual(try JSONCoding.decoder().decode(SubscriptionSource.self, from: pastedData), pasted)
        XCTAssertEqual(try JSONCoding.decoder().decode(SubscriptionSource.self, from: urlData), url)
        XCTAssertTrue(urlJSON.contains("\"key\":\"subscription/synthetic\""))
        XCTAssertFalse(urlJSON.contains("feed"))
    }

    // MARK: - refresh policy encoding

    func testRefreshPolicyEncodingKeepsTheIntervalExplicit() throws {
        let manual = String(decoding: try JSONCoding.encoder().encode(RefreshPolicy(mode: .manual)), as: UTF8.self)
        let interval = String(
            decoding: try JSONCoding.encoder().encode(RefreshPolicy(mode: .interval, interval: 60)),
            as: UTF8.self
        )

        XCTAssertTrue(manual.contains("\"interval\":null"))
        XCTAssertTrue(interval.contains("\"interval\":60"))
    }

    // MARK: - server group membership helpers

    func testServerGroupMembershipHelpers() {
        let member = UUID(uuidString: "00000000-0000-0000-0000-000000000102")!
        let outsider = UUID(uuidString: "00000000-0000-0000-0000-000000000103")!
        let group = ServerGroup(
            id: groupID,
            name: "Group",
            mode: .manual,
            members: [serverID, member],
            selectionPolicy: .manual
        )

        XCTAssertTrue(group.contains(member))
        XCTAssertFalse(group.contains(outsider))
        XCTAssertEqual(group.memberIndex(of: member), 1)
        XCTAssertNil(group.memberIndex(of: outsider))
    }

    // MARK: - route input

    func testRouteInputMemberwiseInit() {
        let input = RouteInput(host: "example.com", ip: "10.0.0.1", port: 443, network: "tcp")

        XCTAssertEqual(input.host, "example.com")
        XCTAssertEqual(input.ip, "10.0.0.1")
        XCTAssertEqual(input.port, 443)
        XCTAssertEqual(input.network, "tcp")

        let empty = RouteInput()
        XCTAssertNil(empty.host)
        XCTAssertNil(empty.ip)
        XCTAssertNil(empty.port)
        XCTAssertNil(empty.network)
    }

    // MARK: - route matcher coding

    func testRouteMatcherDecodesEveryKind() throws {
        let cases: [(String, RouteMatcher)] = [
            ("{\"type\":\"domain\",\"value\":\"example.com\"}", .domain("example.com")),
            ("{\"type\":\"ipCIDR\",\"value\":\"10.0.0.0/8\"}", .ipCIDR("10.0.0.0/8")),
            ("{\"type\":\"port\",\"value\":443}", .port(443)),
            ("{\"type\":\"portRange\",\"lower\":80,\"upper\":443}", .portRange(lower: 80, upper: 443)),
            ("{\"type\":\"network\",\"value\":\"tcp\"}", .network("tcp")),
        ]

        for (json, expected) in cases {
            XCTAssertEqual(
                try JSONCoding.decoder().decode(RouteMatcher.self, from: Data(json.utf8)),
                expected,
                json
            )
        }
    }

    func testRouteMatcherEncodesEveryKind() throws {
        let cases: [(RouteMatcher, [String])] = [
            (.domain("example.com"), ["\"type\":\"domain\"", "\"value\":\"example.com\""]),
            (.domainSuffix("example.org"), ["\"type\":\"domainSuffix\"", "\"value\":\"example.org\""]),
            (.ipCIDR("10.0.0.0/8"), ["\"type\":\"ipCIDR\"", "\"value\":\"10.0.0.0/8\""]),
            (.port(443), ["\"type\":\"port\"", "\"value\":443"]),
            (.portRange(lower: 80, upper: 443), ["\"type\":\"portRange\"", "\"lower\":80", "\"upper\":443"]),
            (.network("tcp"), ["\"type\":\"network\"", "\"value\":\"tcp\""]),
        ]

        for (matcher, fragments) in cases {
            let data = try JSONCoding.encoder().encode(matcher)
            let json = String(decoding: data, as: UTF8.self)
            for fragment in fragments {
                XCTAssertTrue(json.contains(fragment), "\(fragment) missing from \(json)")
            }
            XCTAssertEqual(try JSONCoding.decoder().decode(RouteMatcher.self, from: data), matcher)
        }
    }

    // MARK: - route action coding

    func testRouteActionDecodesEveryKind() throws {
        let block = try JSONCoding.decoder().decode(RouteAction.self, from: Data("{\"type\":\"block\"}".utf8))
        let group = try JSONCoding.decoder().decode(
            RouteAction.self,
            from: Data("{\"type\":\"group\",\"id\":\"00000000-0000-0000-0000-000000000301\"}".utf8)
        )

        XCTAssertEqual(block, .block)
        XCTAssertEqual(group, .group(groupID))
    }

    func testRouteActionEncodesEveryKind() throws {
        let cases: [(RouteAction, String)] = [
            (.direct, "\"type\":\"direct\""),
            (.block, "\"type\":\"block\""),
            (.group(groupID), "\"type\":\"group\""),
        ]

        for (action, fragment) in cases {
            let data = try JSONCoding.encoder().encode(action)
            let json = String(decoding: data, as: UTF8.self)
            XCTAssertTrue(json.contains(fragment))
            XCTAssertEqual(try JSONCoding.decoder().decode(RouteAction.self, from: data), action)
        }
    }

    // MARK: - in-memory trace types

    func testRuleEvaluationAndRoutingDecisionTraceMemberwiseInits() {
        let evaluation = RuleEvaluation(
            ruleID: UUID(uuidString: "00000000-0000-0000-0000-000000000601")!,
            matched: true,
            reason: "firstMatchingRule",
            matchedMatcher: .domain("example.com")
        )

        XCTAssertTrue(evaluation.matched)
        XCTAssertEqual(evaluation.matchedMatcher, .domain("example.com"))

        let defaulted = RuleEvaluation(
            ruleID: evaluation.ruleID,
            matched: false,
            reason: "noMatchingMatcher"
        )
        XCTAssertNil(defaulted.matchedMatcher)

        let input = RouteInput(host: "example.com")
        let trace = RoutingDecisionTrace(
            input: input,
            normalizedInput: input,
            evaluations: [evaluation],
            finalDecision: .group(groupID),
            selectedGroup: groupID,
            selectedServer: serverID
        )

        XCTAssertEqual(trace.finalDecision, .group(groupID))
        XCTAssertEqual(trace.selectedGroup, groupID)
        XCTAssertEqual(trace.selectedServer, serverID)
        XCTAssertEqual(trace.evaluations, [evaluation])
    }

    // MARK: - schema version during decode

    func testAppConfigDecodingRejectsAMismatchedSchemaVersion() throws {
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONCoding.encoder().encode(validConfig())) as? [String: Any]
        )
        object["schemaVersion"] = 2
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try JSONCoding.decoder().decode(AppConfig.self, from: data)) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .invalidSchemaVersion(2))
        }
    }

    // MARK: - validateForPersistence

    func testValidateForPersistenceAcceptsAValidConfig() throws {
        XCTAssertNoThrow(try validConfig().validateForPersistence())
    }

    func testValidateForPersistenceThrowsTheSchemaVersion() {
        XCTAssertThrowsError(try validConfig(schemaVersion: 2).validateForPersistence()) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .invalidSchemaVersion(2))
        }
    }

    func testValidateForPersistenceThrowsAnUnsafePrivacyPolicy() throws {
        let unsafePrivacy = try JSONCoding.structuralDecoder().decode(
            PrivacyPolicy.self,
            from: Data(
                """
                {
                  "telemetryEnabled": false,
                  "trafficLogging": false,
                  "domainHistory": true,
                  "diagnosticsRetention": "memoryOnly",
                  "redactServerAddresses": true,
                  "redactCredentials": true
                }
                """.utf8
            )
        )

        XCTAssertThrowsError(try validConfig(privacy: unsafePrivacy).validateForPersistence()) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .unsafePrivacyPolicy)
        }
    }

    func testValidateForPersistenceThrowsTheDuplicateServerID() {
        let duplicate = server(id: serverID, name: "Duplicate")

        XCTAssertThrowsError(try validConfig(servers: [server(), duplicate]).validateForPersistence()) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .duplicateServerID(serverID))
        }
    }

    func testValidateForPersistenceThrowsTheUnknownSubscriptionServerReference() {
        let unknown = UUID(uuidString: "00000000-0000-0000-0000-000000000201")!
        let subscription = Subscription(
            id: UUID(),
            name: "Subscription",
            source: SubscriptionSource(kind: .pastedText, displayValue: "pasted text"),
            serverIDs: [unknown],
            refreshPolicy: RefreshPolicy(mode: .manual)
        )

        XCTAssertThrowsError(try validConfig(subscriptions: [subscription]).validateForPersistence()) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .unknownServerReference(unknown))
        }
    }

    func testValidateForPersistenceThrowsTheUnknownGroupServerReference() {
        let unknown = UUID(uuidString: "00000000-0000-0000-0000-000000000202")!
        let group = ServerGroup(
            id: groupID,
            name: "Group",
            mode: .manual,
            members: [unknown],
            selectionPolicy: .manual
        )

        XCTAssertThrowsError(try validConfig(groups: [group]).validateForPersistence()) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .unknownServerReference(unknown))
        }
    }

    func testValidateForPersistenceThrowsTheUnknownRuleGroupReference() {
        let unknown = UUID(uuidString: "00000000-0000-0000-0000-000000000203")!
        let rule = RouteRule(
            id: UUID(),
            enabled: true,
            matchers: [.domain("example.com")],
            action: .group(unknown)
        )
        let routing = RouteSet(rules: [rule], defaultAction: .direct)

        XCTAssertThrowsError(try validConfig(routing: routing).validateForPersistence()) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .unknownGroupReference(unknown))
        }
    }

    func testValidateForPersistenceThrowsTheUnknownDefaultActionGroupReference() {
        let unknown = UUID(uuidString: "00000000-0000-0000-0000-000000000204")!
        let routing = RouteSet(rules: [], defaultAction: .group(unknown))

        XCTAssertThrowsError(try validConfig(routing: routing).validateForPersistence()) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .unknownGroupReference(unknown))
        }
    }

    func testValidateForPersistenceFallsBackToTheAggregatedReport() {
        let invalid = ServerGroup(
            id: groupID,
            name: " ",
            mode: .manual,
            members: [serverID],
            selectionPolicy: .manual
        )

        XCTAssertThrowsError(try validConfig(groups: [invalid]).validateForPersistence()) { error in
            guard let validationError = error as? ConfigValidationError else {
                return XCTFail("Expected ConfigValidationError, got \(error)")
            }
            XCTAssertTrue(validationError.issues.contains {
                $0.code == "invalidGroup" && $0.path == "groups[0].name"
            })
        }
    }

    // MARK: - helpers

    private func validConfig(
        schemaVersion: Int = 1,
        subscriptions: [Subscription] = [],
        groups: [ServerGroup] = [],
        routing: RouteSet = RouteSet(rules: [], defaultAction: .direct),
        privacy: PrivacyPolicy = PrivacyPolicy(),
        servers: [Server]? = nil
    ) -> AppConfig {
        AppConfig(
            schemaVersion: schemaVersion,
            subscriptions: subscriptions,
            groups: groups,
            routing: routing,
            dns: DNSPolicy(mode: .system),
            privacy: privacy,
            servers: servers ?? [server()]
        )
    }

    private func server(id: UUID? = nil, name: String = "Synthetic Server") -> Server {
        Server(
            id: id ?? serverID,
            name: name,
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            transport: TransportOptions(kind: "tcp")
        )
    }
}
