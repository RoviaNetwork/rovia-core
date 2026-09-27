import Foundation
import XCTest
@testable import RoviaConfig

final class ConfigValidationTests: XCTestCase {
    func testCurrentSchemaVersionIsOne() {
        XCTAssertEqual(CanonicalConfigLoader.currentSchemaVersion, 1)
    }

    func testLoaderRejectsFutureSchemaVersion() throws {
        var object = try encodedObject(from: validConfig())
        object["schemaVersion"] = 2
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data)) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .invalidSchemaVersion(2))
        }
    }

    func testLoaderPreservesSemanticIssueCodeAndPath() throws {
        var object = try encodedObject(from: validConfig())
        object["subscriptions"] = [[
            "id": "00000000-0000-0000-0000-000000000401",
            "name": "Invalid refresh",
            "source": ["kind": "pastedText", "displayValue": "pasted text"],
            "serverIDs": [String](),
            "refreshPolicy": ["mode": "interval", "interval": 0]
        ]]
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data)) { error in
            guard let validationError = error as? ConfigValidationError else {
                return XCTFail("Expected ConfigValidationError")
            }
            XCTAssertTrue(validationError.issues.contains {
                $0.code == "invalidRefreshPolicy" && $0.path == "subscriptions[0].refreshPolicy.interval"
            })
        }
    }

    func testLoaderReportsTransportSecretIssueWithStablePath() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/config/secret-bearing-transport.json")
        let data = try Data(contentsOf: url)

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data)) { error in
            guard let validationError = error as? ConfigValidationError else {
                return XCTFail("Expected ConfigValidationError")
            }
            XCTAssertTrue(validationError.issues.contains {
                $0.code == "unsafeTransportOption" && $0.path == "servers[0].transport.options"
            })
        }
    }

    func testDirectAppConfigDecoderRemainsStructuralForSemanticIssues() throws {
        var object = try encodedObject(from: validConfig())
        object["subscriptions"] = [[
            "id": "00000000-0000-0000-0000-000000000402",
            "name": "Invalid refresh",
            "source": ["kind": "pastedText", "displayValue": "pasted text"],
            "serverIDs": [String](),
            "refreshPolicy": ["mode": "interval", "interval": 0]
        ]]
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertNoThrow(try JSONCoding.decoder().decode(AppConfig.self, from: data))
    }

    func testLoaderRejectsUnknownNestedFields() throws {
        var object = try encodedObject(from: validConfig())
        var endpoint = try XCTUnwrap((object["servers"] as? [[String: Any]])?.first?["endpoint"] as? [String: Any])
        endpoint["unexpected"] = true
        object["servers"] = [
            [
                "id": "00000000-0000-0000-0000-000000000101",
                "name": "Synthetic Server",
                "protocolKind": "vless",
                "endpoint": endpoint,
                "credential": NSNull(),
                "transport": ["kind": "tcp", "options": [String: Any]()],
                "tls": ["serverName": "synthetic.example", "allowInsecure": false, "alpn": [String]()],
                "tags": ["synthetic"]
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data))
    }

    func testDirectDecoderRejectsUnknownNestedFields() {
        let data = Data(
            """
            {
              "id": "00000000-0000-0000-0000-000000000101",
              "name": "Synthetic Server",
              "protocolKind": "vless",
              "endpoint": {"host": "synthetic.example", "port": 443, "unexpected": true},
              "credential": null,
              "transport": {"kind": "tcp", "options": {}},
              "tls": null,
              "tags": []
            }
            """.utf8
        )

        XCTAssertThrowsError(try JSONCoding.decoder().decode(Endpoint.self, from: Data("{\"host\":\"synthetic.example\",\"port\":443,\"unexpected\":true}".utf8)))
        XCTAssertThrowsError(try JSONCoding.decoder().decode(Server.self, from: data))
    }

    func testDuplicateServerIDsAreReported() {
        let id = UUID(uuidString: "00000000-0000-0000-0000-000000000101")!
        let config = validConfig(servers: [server(id: id), server(id: id, name: "Duplicate")])

        let report = config.validationReport()

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.issues.contains { $0.code == "duplicateServerID" })
        XCTAssertTrue(report.issues.contains { $0.path == "servers[1].id" })
    }

    func testUnknownReferencesAreReportedTogether() {
        let missingServer = UUID(uuidString: "00000000-0000-0000-0000-000000000201")!
        let missingGroup = UUID(uuidString: "00000000-0000-0000-0000-000000000202")!
        let config = validConfig(
            subscriptions: [subscription(serverIDs: [missingServer])],
            groups: [group(members: [missingServer])],
            routing: RouteSet(
                rules: [RouteRule(id: UUID(), enabled: true, matchers: [.domain("example.com")], action: .group(missingGroup))],
                defaultAction: .direct
            )
        )

        let report = config.validationReport()

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.issues.contains { $0.code == "unknownServerReference" })
        XCTAssertTrue(report.issues.contains { $0.code == "unknownGroupReference" })
    }

    func testInvalidRouteMatcherIsReported() {
        let config = validConfig(
            routing: RouteSet(
                rules: [RouteRule(id: UUID(), enabled: true, matchers: [.ipCIDR("10.0.0.0/99")], action: .direct)],
                defaultAction: .direct
            )
        )

        let report = config.validationReport()

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.issues.contains { $0.code == "invalidRouteMatcher" })
        XCTAssertTrue(report.issues.contains { $0.path == "routing.rules[0].matchers[0]" })
    }

    func testInvalidRefreshPoliciesAreReported() {
        let invalid = [
            RefreshPolicy(mode: .interval, interval: nil),
            RefreshPolicy(mode: .interval, interval: 0),
            RefreshPolicy(mode: .manual, interval: 60)
        ]
        let config = validConfig(
            subscriptions: invalid.enumerated().map { index, policy in
                subscription(serverIDs: [], refreshPolicy: policy, name: "Subscription \(index)")
            }
        )

        let report = config.validationReport()

        XCTAssertEqual(report.issues.filter { $0.code == "invalidRefreshPolicy" }.count, invalid.count)
    }

    func testURLSourceRequiresSecretReference() {
        let config = validConfig(
            subscriptions: [subscription(
                source: SubscriptionSource(kind: .url, displayValue: "https://example.com/private-token"),
                serverIDs: []
            )]
        )

        let report = config.validationReport()

        XCTAssertTrue(report.issues.contains { $0.code == "missingSourceSecretReference" })
        XCTAssertFalse(report.issues.contains { $0.message.contains("private-token") })
    }

    func testLoaderRejectsRawSSURLSource() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/config/raw-ssr-url-source.json")
        let data = try Data(contentsOf: url)

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data)) { error in
            XCTAssertFalse(String(describing: error).contains("ssr-url-canary"))
        }
    }

    func testLoaderRejectsURLSourceWithUserinfo() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/config/url-userinfo-source.json")
        let data = try Data(contentsOf: url)

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data)) { error in
            XCTAssertFalse(String(describing: error).contains("url-user-canary"))
            XCTAssertFalse(String(describing: error).contains("url-password-canary"))
        }
    }

    func testLoaderAcceptsSanitizedSourceMetadataFixture() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/config/sanitized-source-metadata.json")
        let data = try Data(contentsOf: url)

        let config = try CanonicalConfigLoader.load(data)

        XCTAssertTrue(config.validationReport().isValid)
    }

    func testValidationRejectsNonHTTPSURLDisplay() {
        let config = validConfig(
            subscriptions: [subscription(
                source: SubscriptionSource(
                    kind: .url,
                    displayValue: "ssr://raw-url-canary",
                    secretReference: SecretReference(key: "subscription/raw")
                ),
                serverIDs: []
            )]
        )

        let report = config.validationReport()

        XCTAssertTrue(report.issues.contains { $0.code == "invalidSourceDisplay" })
    }

    func testValidationRejectsRawProxyDisplayForPastedSource() {
        let config = validConfig(
            subscriptions: [subscription(
                source: SubscriptionSource(kind: .pastedText, displayValue: "ssr://raw-pasted-canary"),
                serverIDs: []
            )]
        )

        let report = config.validationReport()

        XCTAssertTrue(report.issues.contains { $0.code == "invalidSourceDisplay" })
    }

    func testPastedSourceStoresOnlySanitizedMetadata() {
        let source = SubscriptionSource(
            kind: .pastedText,
            displayValue: "vmess://uuid-canary@example.com:443?token=token-canary"
        )

        XCTAssertFalse(source.displayValue.contains("canary"))
        XCTAssertFalse(source.displayValue.contains("token"))
    }

    func testTransportOptionsRejectSecretBearingKeysDuringDecode() {
        let data = Data("{\"kind\":\"ws\",\"options\":{\"password\":\"password-canary\"}}".utf8)

        XCTAssertThrowsError(try JSONCoding.decoder().decode(TransportOptions.self, from: data)) { error in
            XCTAssertFalse(String(describing: error).contains("password-canary"))
        }
    }

    func testTransportSecretKeyDetectionCoversCanonicalVocabulary() throws {
        let keys = [
            "password", "passwd", "passphrase", "pwd", "psk", "token", "secret", "uuid", "credential",
            "private key", "private_key", "private-key", "authorization", "Proxy-Authorization"
        ]

        for key in keys {
            let object: [String: Any] = ["kind": "ws", "options": [key: "transport-secret-canary"]]
            let data = try JSONSerialization.data(withJSONObject: object)
            XCTAssertThrowsError(try JSONCoding.decoder().decode(TransportOptions.self, from: data), key) { error in
                XCTAssertFalse(String(describing: error).contains("transport-secret-canary"), key)
            }
        }
    }

    func testTransportSecretKeyDetectionRejectsSeparatorObfuscationButAllowsMonkey() throws {
        let secretKeys = ["p-wd", "to-ken", "co-okie", "a-uth"]
        for key in secretKeys {
            let object: [String: Any] = ["kind": "ws", "options": [key: "transport-secret-canary"]]
            let data = try JSONSerialization.data(withJSONObject: object)
            XCTAssertThrowsError(try JSONCoding.decoder().decode(TransportOptions.self, from: data), key)
        }

        let safeObject: [String: Any] = ["kind": "ws", "options": ["monkey": "safe"]]
        let safeData = try JSONSerialization.data(withJSONObject: safeObject)
        XCTAssertNoThrow(try JSONCoding.decoder().decode(TransportOptions.self, from: safeData))
    }

    func testURLSourceEncodingRequiresSecretReference() {
        let source = SubscriptionSource(kind: .url, displayValue: "https://example.com/private")

        XCTAssertThrowsError(try JSONCoding.encoder().encode(source))
    }

    func testURLSourceDecodingRequiresSecretReference() {
        let data = Data("{\"kind\":\"url\",\"displayValue\":\"https://example.com/private\"}".utf8)

        XCTAssertThrowsError(try JSONCoding.decoder().decode(SubscriptionSource.self, from: data))
    }

    func testRouteEnumDecodersRejectFieldsFromAnotherBranch() {
        let actionData = Data("{\"type\":\"direct\",\"id\":\"00000000-0000-0000-0000-000000000001\"}".utf8)
        let matcherData = Data("{\"type\":\"domain\",\"value\":\"example.com\",\"lower\":1}".utf8)

        XCTAssertThrowsError(try JSONCoding.decoder().decode(RouteAction.self, from: actionData))
        XCTAssertThrowsError(try JSONCoding.decoder().decode(RouteMatcher.self, from: matcherData))
    }

    func testDirectAppConfigDecoderLeavesReferencesForValidationReport() throws {
        var object = try encodedObject(from: validConfig())
        object["groups"] = [[
            "id": "00000000-0000-0000-0000-000000000301",
            "name": "Group",
            "mode": "manual",
            "members": ["00000000-0000-0000-0000-000000000302"],
            "selectionPolicy": "manual"
        ]]
        let data = try JSONSerialization.data(withJSONObject: object)

        let config = try JSONCoding.decoder().decode(AppConfig.self, from: data)
        XCTAssertTrue(config.validationReport().issues.contains { $0.code == "unknownServerReference" })
    }

    func testTransportOptionsRejectSecretBearingKeysDuringEncode() {
        let options = TransportOptions(kind: "ws", options: ["authorization": "Bearer canary"])

        XCTAssertThrowsError(try JSONCoding.encoder().encode(options)) { error in
            XCTAssertFalse(String(describing: error).contains("canary"))
        }
    }

    func testValidatedReturnsValidConfigUnchanged() throws {
        let config = validConfig()

        XCTAssertEqual(try config.validated(), config)
    }

    func testCanonicalEncodingKeepsNullableServerFieldsExplicit() throws {
        let data = try JSONCoding.encoder().encode(validConfig())
        let json = String(decoding: data, as: UTF8.self)

        XCTAssertTrue(json.contains("\"credential\":null"))
        XCTAssertTrue(json.contains("\"tls\":null"))
    }

    func testValidatedThrowsAnAggregatedValidationError() {
        let id = UUID()
        let config = validConfig(
            subscriptions: [subscription(serverIDs: [UUID()])],
            groups: [group(id: id, members: [UUID()])],
            servers: [server(id: id), server(id: id, name: "Duplicate")]
        )

        XCTAssertThrowsError(try config.validated()) { error in
            guard let validationError = error as? ConfigValidationError else {
                return XCTFail("Expected ConfigValidationError")
            }
            XCTAssertGreaterThan(validationError.report.issues.count, 1)
        }
    }

    // MARK: - Secret reference keys

    func testASecretReferenceKeyMustBePrintableASCIIWithinTheLengthBound() {
        XCTAssertTrue(SecretReference.isValidKey("subscription/sanitized"))
        XCTAssertTrue(SecretReference.isValidKey("!~"))
        XCTAssertTrue(SecretReference.isValidKey(String(repeating: "k", count: 512)))

        for (label, key) in [
            ("empty", ""),
            ("space", "subscription/ sanitized"),
            ("tab", "subscription\tsanitized"),
            ("newline", "subscription\nsanitized"),
            ("trailing newline", "subscription/sanitized\n"),
            ("bell", "subscription\u{7}sanitized"),
            ("delete", "subscription\u{7F}sanitized"),
            ("non-ascii", "server/credential-\u{2705}"),
            ("one byte over the limit", String(repeating: "k", count: 513)),
        ] {
            XCTAssertFalse(
                SecretReference.isValidKey(key),
                "a secret reference key must refuse \(label)"
            )
        }
    }

    func testValidationReportsAnUnusableSecretReferenceKeyOnASubscriptionSource() throws {
        let subscription = Subscription(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000401")!,
            name: "URL source",
            source: SubscriptionSource(
                kind: .url,
                displayValue: "https://synthetic.example/\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}",
                secretReference: SecretReference(key: "subscription/ credential")
            ),
            serverIDs: [],
            refreshPolicy: RefreshPolicy(mode: .manual)
        )
        let report = validConfig(subscriptions: [subscription]).validationReport()

        XCTAssertTrue(
            report.issues.contains {
                $0.code == "invalidSecretReferenceKey" && $0.path == "subscriptions[0].source.secretReference.key"
            },
            "expected an invalidSecretReferenceKey issue, got \(report.issues)"
        )
    }

    func testValidationReportsAnUnusableSecretReferenceKeyOnAServerCredential() throws {
        var credentialServer = server()
        credentialServer = Server(
            id: credentialServer.id,
            name: credentialServer.name,
            protocolKind: credentialServer.protocolKind,
            endpoint: credentialServer.endpoint,
            credential: SecretReference(key: "server/credential-\u{2705}"),
            transport: credentialServer.transport,
            tls: credentialServer.tls,
            tags: credentialServer.tags
        )
        let report = validConfig(servers: [credentialServer]).validationReport()

        XCTAssertTrue(
            report.issues.contains {
                $0.code == "invalidSecretReferenceKey" && $0.path == "servers[0].credential.key"
            },
            "expected an invalidSecretReferenceKey issue, got \(report.issues)"
        )
    }

    func testAUsableSecretReferenceKeyProducesNoIssue() throws {
        let subscription = Subscription(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000402")!,
            name: "URL source",
            source: SubscriptionSource(
                kind: .url,
                displayValue: "https://synthetic.example/\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}",
                secretReference: SecretReference(key: "subscription/sanitized")
            ),
            serverIDs: [],
            refreshPolicy: RefreshPolicy(mode: .manual)
        )
        let report = validConfig(subscriptions: [subscription]).validationReport()

        XCTAssertFalse(
            report.issues.contains { $0.code == "invalidSecretReferenceKey" },
            "a printable ASCII key within the bound must not be reported, got \(report.issues)"
        )
    }

    func testTheRawJSONWalkRefusesAnUnusableSecretReferenceKey() throws {
        var object = try encodedObject(from: validConfig())
        object["subscriptions"] = [[
            "id": "00000000-0000-0000-0000-000000000403",
            "name": "URL source",
            "source": [
                "kind": "url",
                "displayValue": "https://synthetic.example/\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}",
                "secretReference": ["kind": "keychain", "key": "subscription\nsanitized"]
            ],
            "serverIDs": [String](),
            "refreshPolicy": ["mode": "manual", "interval": NSNull()]
        ]]
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data)) { error in
            // The raw-JSON walk refuses by throwing rather than by collecting an
            // issue, because it never builds a model. Either way the key is
            // refused before it can reach a caller.
            XCTAssertEqual(
                error as? CanonicalConfigError,
                .invalidField(path: "subscriptions[].source.secretReference.key"),
                "the JSON walk must apply the same rule as the model, got \(error)"
            )
        }
    }

    private func validConfig(
        subscriptions: [Subscription] = [],
        groups: [ServerGroup] = [],
        routing: RouteSet = RouteSet(rules: [], defaultAction: .direct),
        servers: [Server]? = nil
    ) -> AppConfig {
        AppConfig(
            schemaVersion: 1,
            subscriptions: subscriptions,
            groups: groups,
            routing: routing,
            dns: DNSPolicy(mode: .system),
            privacy: PrivacyPolicy(),
            servers: servers ?? [server()]
        )
    }

    private func server(id: UUID = UUID(), name: String = "Synthetic Server") -> Server {
        Server(
            id: id,
            name: name,
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            transport: TransportOptions(kind: "tcp")
        )
    }

    private func group(
        id: UUID = UUID(),
        members: [UUID] = [],
        mode: GroupMode = .manual
    ) -> ServerGroup {
        ServerGroup(id: id, name: "Group", mode: mode, members: members, selectionPolicy: .manual)
    }

    private func subscription(
        source: SubscriptionSource = SubscriptionSource(kind: .pastedText, displayValue: "pasted text"),
        serverIDs: [UUID],
        refreshPolicy: RefreshPolicy = RefreshPolicy(mode: .manual),
        name: String = "Subscription"
    ) -> Subscription {
        Subscription(
            id: UUID(),
            name: name,
            source: source,
            serverIDs: serverIDs,
            refreshPolicy: refreshPolicy
        )
    }

    private func encodedObject(from config: AppConfig) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: JSONCoding.encoder().encode(config)) as? [String: Any])
    }
}

/// The two normalisers had edges where they returned something rather than
/// nothing. Both are load-bearing in `RouteEvaluator`, which normalises both
/// sides of a domain comparison and refuses an address it cannot parse.
final class DegenerateInputTests: XCTestCase {
    // MARK: - IPv4-mapped IPv6

    func test_an_ipv4_mapped_address_is_accepted_and_normalised_to_ipv4() {
        XCTAssertEqual(
            CanonicalRouteMatcherValidator.normalizeIPAddress("::ffff:1.2.3.4"),
            "1.2.3.4",
        )
        XCTAssertEqual(
            CanonicalRouteMatcherValidator.parseIPAddress("::ffff:1.2.3.4")?.count,
            4,
        )
    }

    func test_the_mapped_form_is_case_insensitive_and_tolerates_space() {
        XCTAssertEqual(
            CanonicalRouteMatcherValidator.normalizeIPAddress("  ::FFFF:10.0.0.1 "),
            "10.0.0.1",
        )
    }

    func test_a_plain_ipv4_address_still_normalises_to_itself() {
        for value in ["1.2.3.4", "10.0.0.1", "255.255.255.255"] {
            XCTAssertEqual(CanonicalRouteMatcherValidator.normalizeIPAddress(value), value)
        }
    }

    func test_a_plain_ipv6_address_still_normalises_to_itself() {
        XCTAssertEqual(
            CanonicalRouteMatcherValidator.normalizeIPAddress("2001:db8::1"),
            "2001:db8::1",
        )
    }

    func test_ipv4_rules_match_a_mapped_address() {
        XCTAssertTrue(
            try CanonicalRouteMatcherValidator.cidr("0.0.0.0/0", contains: "::ffff:1.2.3.4")
        )
        XCTAssertTrue(
            try CanonicalRouteMatcherValidator.cidr("1.2.3.0/24", contains: "::ffff:1.2.3.4")
        )
        XCTAssertFalse(
            try CanonicalRouteMatcherValidator.cidr("9.9.9.0/24", contains: "::ffff:1.2.3.4")
        )
    }

    func test_an_ipv6_rule_does_not_capture_a_mapped_address() {
        // Documented consequence of accept-and-normalise: the candidate is four
        // bytes and the network is sixteen, so "::/0" does not match. The rule
        // that means "everything IPv6" must not silently absorb an IPv4 address.
        XCTAssertFalse(
            try CanonicalRouteMatcherValidator.cidr("::/0", contains: "::ffff:1.2.3.4")
        )
    }

    func test_a_mapped_looking_string_with_a_bad_tail_is_still_refused() {
        for value in ["::ffff:1.2.3", "::ffff:999.1.2.3", "::ffff:", "::ffffx:1.2.3.4"] {
            XCTAssertNil(
                CanonicalRouteMatcherValidator.normalizeIPAddress(value),
                "\(value) was accepted",
            )
        }
    }

    // MARK: - degenerate domains

    func test_degenerate_domains_normalise_to_nothing() {
        // ".." used to normalise to "." and "..." to "..", both non-empty, and a
        // host comparison would match them.
        for value in [".", "..", "...", "....", " ", ".example.com", "example..com"] {
            XCTAssertNil(
                CanonicalRouteMatcherValidator.normalizeDomain(value),
                "\(value.debugDescription) normalised to something",
            )
        }
    }

    func test_a_trailing_dot_is_still_removed() {
        XCTAssertEqual(
            CanonicalRouteMatcherValidator.normalizeDomain("example.com."),
            "example.com",
        )
        XCTAssertEqual(
            CanonicalRouteMatcherValidator.normalizeDomain("  Example.COM.  "),
            "example.com",
        )
    }

    func test_a_degenerate_domain_normalises_to_nothing_on_both_sides() {
        // This is the state the evaluator has to cope with, and it is why the
        // evaluator's own comparison is fixed: both sides become nil, and
        // `nil == nil` is true in Swift. The evaluator must therefore check that
        // both are present rather than comparing the two Optionals. That check
        // lives in RoviaRouting and is exercised by
        // core/routing/Tests/RoviaRoutingTests.
        for value in ["..", ".", "..."] {
            XCTAssertNil(CanonicalRouteMatcherValidator.normalizeDomain(value))
        }
    }
}
