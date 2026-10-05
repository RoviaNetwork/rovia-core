import Foundation
import XCTest
@testable import RoviaConfig

/// Coverage of `CanonicalConfigLoader`'s overloads and of
/// `CanonicalJSONShapeValidator`'s per-field refusal paths. Each malformed
/// document is a fully valid configuration with exactly one field broken, so
/// the thrown error names the broken field and nothing else.
final class ConfigShapeValidatorTests: XCTestCase {
    private let serverID = UUID(uuidString: "00000000-0000-0000-0000-000000000101")!
    private let groupID = UUID(uuidString: "00000000-0000-0000-0000-000000000301")!
    private let subscriptionID = UUID(uuidString: "00000000-0000-0000-0000-000000000401")!
    private let ruleID = UUID(uuidString: "00000000-0000-0000-0000-000000000601")!

    // MARK: - loader overloads

    func testLoaderAcceptsAFullConfigurationExercisingEveryShape() throws {
        let data = try JSONCoding.encoder().encode(fullConfig())

        let loaded = try CanonicalConfigLoader.load(data)

        XCTAssertEqual(loaded, fullConfig())
        XCTAssertTrue(loaded.validationReport().isValid)
    }

    func testLoaderLoadsConfigurationFromAString() throws {
        let data = try JSONCoding.encoder().encode(fullConfig())
        let string = String(decoding: data, as: UTF8.self)

        XCTAssertEqual(try CanonicalConfigLoader.load(string), fullConfig())
    }

    func testLoaderLoadsConfigurationFromAFileURL() throws {
        let data = try JSONCoding.encoder().encode(fullConfig())
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("json")
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertEqual(try CanonicalConfigLoader.load(url), fullConfig())
        XCTAssertEqual(try CanonicalConfigLoader.load(contentsOf: url), fullConfig())
    }

    func testLoaderRejectsNonJSONAndNonObjectDocuments() {
        XCTAssertThrowsError(try CanonicalConfigLoader.load(Data("not json".utf8))) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .invalidJSON)
        }
        XCTAssertThrowsError(try CanonicalConfigLoader.load(Data("[1,2,3]".utf8))) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .invalidJSON)
        }
    }

    func testLoaderRejectsAMissingNonBooleanOrFractionalSchemaVersion() throws {
        try assertLoadThrows(.missingSchemaVersion) { object in
            object.removeValue(forKey: "schemaVersion")
        }
        try assertLoadThrows(.missingSchemaVersion) { object in
            object["schemaVersion"] = true
        }
        try assertLoadThrows(.missingSchemaVersion) { object in
            object["schemaVersion"] = 1.5
        }
    }

    func testLoaderMapsADecodeFailureToTheFallbackPath() throws {
        // An integral JSON number that overflows Int passes the shape walk but
        // cannot decode into Endpoint.port. The parser reports the failure
        // without a coding path, so the loader falls back to "config".
        try assertLoadThrows(.invalidField(path: "config")) { object in
            object["servers"] = [[
                "id": "00000000-0000-0000-0000-000000000101",
                "name": "Synthetic Server",
                "protocolKind": "vless",
                "endpoint": ["host": "synthetic.example", "port": 1e30],
                "credential": NSNull(),
                "transport": ["kind": "tcp", "options": [String: String]()],
                "tls": NSNull(),
                "tags": [String]()
            ]]
        }
    }

    func testMigrationMapsADecodeFailureToTheFallbackPath() throws {
        var object = try fullConfigObject()
        object["servers"] = [[
            "id": "00000000-0000-0000-0000-000000000101",
            "name": "Synthetic Server",
            "protocolKind": "vless",
            "endpoint": ["host": "synthetic.example", "port": 1e30],
            "credential": NSNull(),
            "transport": ["kind": "tcp", "options": [String: String]()],
            "tls": NSNull(),
            "tags": [String]()
        ]]
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try CanonicalConfigLoader.migrate(data)) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .invalidField(path: "config"))
        }
    }

    func testMigrationOfAValidConfigReturnsItUnchanged() throws {
        XCTAssertEqual(try CanonicalConfigLoader.migrate(fullConfig()), fullConfig())

        let invalid = AppConfig(
            schemaVersion: 1,
            subscriptions: [],
            groups: [ServerGroup(id: groupID, name: "", mode: .manual, members: [serverID], selectionPolicy: .manual)],
            routing: RouteSet(rules: [], defaultAction: .direct),
            dns: DNSPolicy(mode: .system),
            privacy: PrivacyPolicy(),
            servers: [server()]
        )
        XCTAssertThrowsError(try CanonicalConfigLoader.migrate(invalid)) { error in
            guard let validationError = error as? ConfigValidationError else {
                return XCTFail("Expected ConfigValidationError, got \(error)")
            }
            XCTAssertTrue(validationError.issues.contains {
                $0.code == "invalidGroup" && $0.path == "groups[0].name"
            })
        }
    }

    // MARK: - groups shape

    func testGroupElementMustBeAnObject() throws {
        try assertLoadThrows(.invalidField(path: "groups[]")) { object in
            object["groups"] = [42]
        }
    }

    func testGroupRejectsUnknownFields() throws {
        try assertLoadThrows(.unknownField(path: "groups[]")) { object in
            object["groups"] = [[
                "id": "00000000-0000-0000-0000-000000000301",
                "name": "Group",
                "mode": "manual",
                "members": [String](),
                "selectionPolicy": "manual",
                "unexpected": true
            ]]
        }
    }

    func testGroupRequiresEveryDeclaredField() throws {
        try assertLoadThrows(.invalidField(path: "groups[].mode")) { object in
            object["groups"] = [[
                "id": "00000000-0000-0000-0000-000000000301",
                "name": "Group",
                "members": [String](),
                "selectionPolicy": "manual"
            ]]
        }
    }

    func testGroupFieldsMustCarryTheRightShapes() throws {
        try assertLoadThrows(.invalidField(path: "groups[].id")) { object in
            object["groups"] = [groupObject(id: "not-a-uuid")]
        }
        try assertLoadThrows(.invalidField(path: "groups[].name")) { object in
            object["groups"] = [groupObject(name: 42)]
        }
        try assertLoadThrows(.invalidField(path: "groups[].mode")) { object in
            object["groups"] = [groupObject(mode: "random")]
        }
        try assertLoadThrows(.invalidField(path: "groups[].members")) { object in
            object["groups"] = [groupObject(members: "not-an-array")]
        }
        try assertLoadThrows(.invalidField(path: "groups[].members")) { object in
            object["groups"] = [groupObject(members: ["not-a-uuid"])]
        }
        try assertLoadThrows(.invalidField(path: "groups[].selectionPolicy")) { object in
            object["groups"] = [groupObject(selectionPolicy: "random")]
        }
    }

    // MARK: - routing shape

    func testRouteSetMustBeAnObjectWithARuleArray() throws {
        try assertLoadThrows(.invalidField(path: "routing")) { object in
            object["routing"] = 42
        }
        try assertLoadThrows(.invalidField(path: "routing.rules")) { object in
            object["routing"] = ["rules": 42, "defaultAction": ["type": "direct"]]
        }
    }

    func testRouteRuleElementMustBeAnObject() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[]")) { object in
            object["routing"] = ["rules": [42], "defaultAction": ["type": "direct"]]
        }
    }

    func testRouteRuleRequiresEnabledAsABoolean() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[].enabled")) { object in
            object["routing"] = ["rules": [ruleObject(enabled: "yes")], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.rules[].enabled")) { object in
            object["routing"] = ["rules": [[
                "id": "00000000-0000-0000-0000-000000000601",
                "matchers": [["type": "network", "value": "tcp"]],
                "action": ["type": "direct"]
            ]], "defaultAction": ["type": "direct"]]
        }
    }

    func testRouteRuleMatchersMustBeAnArrayAndNoteMustBeAString() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[].matchers")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: 42)], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.rules[].note")) { object in
            object["routing"] = ["rules": [ruleObject(note: 42)], "defaultAction": ["type": "direct"]]
        }
    }

    // MARK: - route matcher shape

    func testRouteMatcherMustBeAnObjectWithAStringType() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[]")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: [42])], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[].type")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: [["value": "example.com"]])], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[].type")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: [["type": 42]])], "defaultAction": ["type": "direct"]]
        }
    }

    func testRouteMatcherRejectsAnUnknownType() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[].type")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: [["type": "bogus", "value": "x"]])], "defaultAction": ["type": "direct"]]
        }
    }

    func testStringValuedMatchersRequireAStringValue() throws {
        for type in ["domain", "domainSuffix", "network", "ipCIDR"] {
            try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[].value")) { object in
                object["routing"] = ["rules": [ruleObject(matchers: [["type": type, "value": 42]])], "defaultAction": ["type": "direct"]]
            }
        }
    }

    func testMatcherRejectsFieldsFromAnotherMatcherKind() throws {
        try assertLoadThrows(.unknownField(path: "routing.rules[].matchers[]")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: [[
                "type": "domain",
                "value": "example.com",
                "lower": 1
            ]])], "defaultAction": ["type": "direct"]]
        }
    }

    func testPortMatcherRequiresAnIntegralNonBooleanNumber() throws {
        for value in ["443", 3.5, true] as [Any] {
            try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[].value")) { object in
                object["routing"] = ["rules": [ruleObject(matchers: [["type": "port", "value": value]])], "defaultAction": ["type": "direct"]]
            }
        }
    }

    func testPortRangeMatcherRequiresBothIntegralBounds() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[].upper")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: [["type": "portRange", "lower": 80]])], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[].lower")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: [["type": "portRange", "lower": "x", "upper": 443]])], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.rules[].matchers[].upper")) { object in
            object["routing"] = ["rules": [ruleObject(matchers: [["type": "portRange", "lower": 80, "upper": 3.5]])], "defaultAction": ["type": "direct"]]
        }
    }

    // MARK: - route action shape

    func testRouteActionMustBeAnObjectWithAStringType() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[].action")) { object in
            object["routing"] = ["rules": [ruleObject(action: 42)], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.rules[].action")) { object in
            object["routing"] = ["rules": [ruleObject(action: ["type": 42])], "defaultAction": ["type": "direct"]]
        }
    }

    func testRouteActionRejectsAnUnknownType() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[].action.type")) { object in
            object["routing"] = ["rules": [ruleObject(action: ["type": "hop"])], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.defaultAction.type")) { object in
            object["routing"] = ["rules": [Any](), "defaultAction": ["type": "hop"]]
        }
    }

    func testGroupActionRequiresAUUIDIdentifier() throws {
        try assertLoadThrows(.invalidField(path: "routing.rules[].action.id")) { object in
            object["routing"] = ["rules": [ruleObject(action: ["type": "group"])], "defaultAction": ["type": "direct"]]
        }
        try assertLoadThrows(.invalidField(path: "routing.rules[].action.id")) { object in
            object["routing"] = ["rules": [ruleObject(action: ["type": "group", "id": "not-a-uuid"])], "defaultAction": ["type": "direct"]]
        }
    }

    func testDirectActionRejectsFieldsFromTheGroupBranch() throws {
        try assertLoadThrows(.unknownField(path: "routing.rules[].action")) { object in
            object["routing"] = ["rules": [ruleObject(action: [
                "type": "direct",
                "id": "00000000-0000-0000-0000-000000000301"
            ])], "defaultAction": ["type": "direct"]]
        }
    }

    // MARK: - subscription source and refresh policy shape

    func testSourceRejectsAnUnknownKind() throws {
        try assertLoadThrows(.invalidField(path: "subscriptions[].source.kind")) { object in
            object["subscriptions"] = [subscriptionObject(source: ["kind": "udp", "displayValue": "x"])]
        }
    }

    func testPastedAndFileSourcesRejectRawProxyShareLinkDisplayValues() throws {
        for kind in ["pastedText", "file"] {
            try assertLoadThrows(.invalidField(path: "subscriptions[].source.displayValue")) { object in
                object["subscriptions"] = [subscriptionObject(source: ["kind": kind, "displayValue": "vless://raw-share-link"])]
            }
        }
    }

    func testRefreshPolicyRejectsAnUnknownMode() throws {
        try assertLoadThrows(.invalidField(path: "subscriptions[].refreshPolicy.mode")) { object in
            object["subscriptions"] = [subscriptionObject(refreshPolicy: ["mode": "weekly"])]
        }
    }

    func testRefreshPolicyIntervalMustBeANonBooleanNumber() throws {
        for interval in [true, "soon"] as [Any] {
            try assertLoadThrows(.invalidField(path: "subscriptions[].refreshPolicy.interval")) { object in
                object["subscriptions"] = [subscriptionObject(refreshPolicy: ["mode": "interval", "interval": interval])]
            }
        }
    }

    func testSubscriptionOptionalFieldsMustCarryTheRightShapes() throws {
        try assertLoadThrows(.invalidField(path: "subscriptions[].contentHash")) { object in
            object["subscriptions"] = [subscriptionObject(contentHash: 42)]
        }
        try assertLoadThrows(.invalidField(path: "subscriptions[].lastRefresh")) { object in
            object["subscriptions"] = [subscriptionObject(lastRefresh: "not-a-date")]
        }
        try assertLoadThrows(.invalidField(path: "subscriptions[].lastRefresh")) { object in
            object["subscriptions"] = [subscriptionObject(lastRefresh: 42)]
        }
    }

    // MARK: - server transport, TLS, and credential shape

    func testTransportOptionsMustBeAStringKeyedStringDictionary() throws {
        try assertLoadThrows(.invalidField(path: "servers[].transport.options")) { object in
            object["servers"] = [serverObject(transport: ["kind": "tcp", "options": "not-a-dictionary"])]
        }
        try assertLoadThrows(.invalidField(path: "servers[].transport.options")) { object in
            object["servers"] = [serverObject(transport: ["kind": "tcp", "options": ["path": 42]])]
        }
    }

    func testTLSOptionsMustBeAnObjectWithBooleanAllowInsecure() throws {
        try assertLoadThrows(.invalidField(path: "servers[].tls")) { object in
            object["servers"] = [serverObject(tls: "not-an-object")]
        }
        try assertLoadThrows(.invalidField(path: "servers[].tls.allowInsecure")) { object in
            object["servers"] = [serverObject(tls: ["allowInsecure": "yes", "alpn": [String]()])]
        }
        try assertLoadThrows(.unknownField(path: "servers[].tls")) { object in
            object["servers"] = [serverObject(tls: ["allowInsecure": false, "alpn": [String](), "unexpected": true])]
        }
        try assertLoadThrows(.invalidField(path: "servers[].tls.alpn")) { object in
            object["servers"] = [serverObject(tls: ["allowInsecure": false, "alpn": [42]])]
        }
    }

    func testCredentialMustBeAKeychainReferenceWithAStringKey() throws {
        try assertLoadThrows(.invalidField(path: "servers[].credential.kind")) { object in
            object["servers"] = [serverObject(credential: ["kind": "file", "key": "server/synthetic"])]
        }
        try assertLoadThrows(.invalidField(path: "servers[].credential.key")) { object in
            object["servers"] = [serverObject(credential: ["kind": "keychain", "key": 42])]
        }
    }

    // MARK: - DNS and privacy shape

    func testDNSPolicyRejectsUnknownModesAndNonStringServers() throws {
        try assertLoadThrows(.invalidField(path: "dns.mode")) { object in
            object["dns"] = ["mode": "bogus", "servers": [String]()]
        }
        try assertLoadThrows(.invalidField(path: "dns.servers")) { object in
            object["dns"] = ["mode": "system", "servers": "not-an-array"]
        }
        try assertLoadThrows(.invalidField(path: "dns.servers")) { object in
            object["dns"] = ["mode": "system", "servers": [42]]
        }
    }

    func testPrivacyPolicyRejectsNonBooleanAndUnknownEnumValues() throws {
        try assertLoadThrows(.invalidField(path: "privacy.telemetryEnabled")) { object in
            var privacy = try XCTUnwrap(object["privacy"] as? [String: Any])
            privacy["telemetryEnabled"] = "yes"
            object["privacy"] = privacy
        }
        try assertLoadThrows(.invalidField(path: "privacy.diagnosticsRetention")) { object in
            var privacy = try XCTUnwrap(object["privacy"] as? [String: Any])
            privacy["diagnosticsRetention"] = "forever"
            object["privacy"] = privacy
        }
    }

    // MARK: - helpers

    private func fullConfig() -> AppConfig {
        AppConfig(
            schemaVersion: 1,
            subscriptions: [
                Subscription(
                    id: subscriptionID,
                    name: "Synthetic Subscription",
                    source: SubscriptionSource(
                        kind: .url,
                        displayValue: "https://subscriptions.example/feed",
                        secretReference: SecretReference(key: "subscription/synthetic")
                    ),
                    serverIDs: [serverID],
                    refreshPolicy: RefreshPolicy(mode: .interval, interval: 3600),
                    lastRefresh: Date(timeIntervalSince1970: 10_000),
                    contentHash: "synthetic-hash"
                )
            ],
            groups: [
                ServerGroup(
                    id: groupID,
                    name: "Synthetic Group",
                    mode: .lowestLatency,
                    members: [serverID],
                    selectionPolicy: .lowestLatency
                )
            ],
            routing: RouteSet(
                rules: [
                    RouteRule(
                        id: ruleID,
                        enabled: true,
                        matchers: [
                            .domain("example.com"),
                            .domainSuffix("example.org"),
                            .ipCIDR("10.0.0.0/8"),
                            .port(443),
                            .portRange(lower: 80, upper: 8080),
                            .network("tcp")
                        ],
                        action: .group(groupID),
                        note: "Synthetic rule"
                    )
                ],
                defaultAction: .block
            ),
            dns: DNSPolicy(mode: .custom, servers: ["1.1.1.1"]),
            privacy: PrivacyPolicy(),
            servers: [server()]
        )
    }

    private func server() -> Server {
        Server(
            id: serverID,
            name: "Synthetic Server",
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            credential: SecretReference(key: "server/synthetic"),
            transport: TransportOptions(kind: "ws", options: ["path": "/synthetic"]),
            tls: TLSOptions(serverName: "synthetic.example", allowInsecure: false, alpn: ["h2"]),
            tags: ["synthetic"]
        )
    }

    private func fullConfigObject() throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONCoding.encoder().encode(fullConfig())) as? [String: Any]
        )
    }

    private func assertLoadThrows(
        _ expected: CanonicalConfigError,
        file: StaticString = #filePath,
        line: UInt = #line,
        mutate: (inout [String: Any]) throws -> Void
    ) throws {
        var object = try fullConfigObject()
        try mutate(&object)
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data), file: file, line: line) { error in
            XCTAssertEqual(error as? CanonicalConfigError, expected, file: file, line: line)
        }
    }

    private func groupObject(
        id: Any = "00000000-0000-0000-0000-000000000301",
        name: Any = "Group",
        mode: Any = "manual",
        members: Any = [String](),
        selectionPolicy: Any = "manual"
    ) -> [String: Any] {
        [
            "id": id,
            "name": name,
            "mode": mode,
            "members": members,
            "selectionPolicy": selectionPolicy
        ]
    }

    private func ruleObject(
        enabled: Any = true,
        matchers: Any = [["type": "network", "value": "tcp"]],
        action: Any = ["type": "direct"],
        note: Any? = nil
    ) -> [String: Any] {
        var rule: [String: Any] = [
            "id": "00000000-0000-0000-0000-000000000601",
            "enabled": enabled,
            "matchers": matchers,
            "action": action
        ]
        if let note {
            rule["note"] = note
        }
        return rule
    }

    private func subscriptionObject(
        source: [String: Any] = ["kind": "pastedText", "displayValue": "pasted text"],
        refreshPolicy: [String: Any] = ["mode": "manual"],
        lastRefresh: Any? = nil,
        contentHash: Any? = nil
    ) -> [String: Any] {
        var subscription: [String: Any] = [
            "id": "00000000-0000-0000-0000-000000000401",
            "name": "Subscription",
            "source": source,
            "serverIDs": [String](),
            "refreshPolicy": refreshPolicy
        ]
        if let lastRefresh {
            subscription["lastRefresh"] = lastRefresh
        }
        if let contentHash {
            subscription["contentHash"] = contentHash
        }
        return subscription
    }

    private func serverObject(
        transport: [String: Any]? = nil,
        tls: Any = NSNull(),
        credential: Any = NSNull()
    ) -> [String: Any] {
        [
            "id": "00000000-0000-0000-0000-000000000101",
            "name": "Synthetic Server",
            "protocolKind": "vless",
            "endpoint": ["host": "synthetic.example", "port": 443],
            "credential": credential,
            "transport": transport ?? ["kind": "tcp", "options": [String: String]()],
            "tls": tls,
            "tags": [String]()
        ]
    }
}
