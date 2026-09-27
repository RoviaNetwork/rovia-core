import Foundation
import XCTest
@testable import RoviaConfig

final class CanonicalModelsTests: XCTestCase {
    func testRoundTripPreservesSchemaAndSecretReference() throws {
        let config = AppConfig(
            schemaVersion: 1,
            subscriptions: [],
            groups: [],
            routing: RouteSet(rules: [], defaultAction: .direct),
            dns: DNSPolicy(mode: .system, servers: []),
            privacy: PrivacyPolicy()
        )

        let data = try JSONCoding.encoder().encode(config)
        let decoded = try JSONCoding.decoder().decode(AppConfig.self, from: data)

        XCTAssertEqual(decoded, config)
        XCTAssertEqual(decoded.schemaVersion, 1)
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("password"))
    }

    func testRouteActionUsesStableJSONShape() throws {
        let groupID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let action = RouteAction.group(groupID)

        let data = try JSONCoding.encoder().encode(action)
        let json = String(decoding: data, as: UTF8.self)

        XCTAssertTrue(json.contains("\"type\":\"group\""))
        XCTAssertTrue(json.contains(groupID.uuidString))
    }

    func testRouteRuleCanBeDecodedFromPortableJSON() throws {
        let data = Data(
            """
            {
              "id": "00000000-0000-0000-0000-000000000002",
              "enabled": true,
              "matchers": [{"type":"domainSuffix","value":"example.com"}],
              "action": {"type":"direct"}
            }
            """.utf8
        )

        let rule = try JSONCoding.decoder().decode(RouteRule.self, from: data)

        XCTAssertEqual(rule.id.uuidString, "00000000-0000-0000-0000-000000000002")
        XCTAssertEqual(rule.matchers, [.domainSuffix("example.com")])
        XCTAssertEqual(rule.action, .direct)
    }

    func testAppConfigPersistsServers() throws {
        let server = Server(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!,
            name: "Synthetic",
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            transport: TransportOptions(kind: "tcp")
        )
        let config = AppConfig(
            schemaVersion: 1,
            subscriptions: [],
            groups: [],
            routing: RouteSet(rules: [], defaultAction: .direct),
            dns: DNSPolicy(mode: .system),
            privacy: PrivacyPolicy(),
            servers: [server]
        )

        let data = try JSONCoding.encoder().encode(config)
        let decoded = try JSONCoding.decoder().decode(AppConfig.self, from: data)

        XCTAssertEqual(decoded.servers, [server])
    }

    func testAppConfigRejectsUnknownRootFields() throws {
        let config = AppConfig(
            schemaVersion: 1,
            subscriptions: [],
            groups: [],
            routing: RouteSet(rules: [], defaultAction: .direct),
            dns: DNSPolicy(mode: .system),
            privacy: PrivacyPolicy()
        )
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONCoding.encoder().encode(config)) as? [String: Any])
        object["unexpected"] = true
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try JSONCoding.decoder().decode(AppConfig.self, from: data))
    }

    func testPrivacyPolicyRejectsUnsafeDecodedValues() {
        let data = Data(
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

        XCTAssertThrowsError(try JSONCoding.decoder().decode(PrivacyPolicy.self, from: data))
    }

    func testInvalidServerPortIsRejectedDuringEncoding() {
        let server = Server(
            id: UUID(),
            name: "Synthetic",
            protocolKind: .vless,
            endpoint: Endpoint(host: "synthetic.example", port: 0),
            transport: TransportOptions(kind: "tcp")
        )
        let config = AppConfig(
            schemaVersion: 1,
            subscriptions: [],
            groups: [],
            routing: RouteSet(rules: [], defaultAction: .direct),
            dns: DNSPolicy(mode: .system),
            privacy: PrivacyPolicy(),
            servers: [server]
        )

        XCTAssertThrowsError(try JSONCoding.encoder().encode(config)) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .invalidServerPort(0))
        }
    }

    func testTransportOptionsRejectSecretBearingKeysDuringEncoding() throws {
        let server = Server(
            id: UUID(),
            name: "Synthetic",
            protocolKind: .trojan,
            endpoint: Endpoint(host: "synthetic.example", port: 443),
            transport: TransportOptions(kind: "tcp", options: ["password": "synthetic-secret"])
        )
        let config = AppConfig(
            schemaVersion: 1,
            subscriptions: [],
            groups: [],
            routing: RouteSet(rules: [], defaultAction: .direct),
            dns: DNSPolicy(mode: .system),
            privacy: PrivacyPolicy(),
            servers: [server]
        )

        XCTAssertThrowsError(try JSONCoding.encoder().encode(config))
    }

    // MARK: - Secret reference keys

    private func decodeSecretReference(key: String) throws -> SecretReference {
        let encodedKey = try JSONEncoder().encode(key)
        let json = "{\"kind\":\"keychain\",\"key\":\(String(decoding: encodedKey, as: UTF8.self))}"
        return try JSONCoding.decoder().decode(SecretReference.self, from: Data(json.utf8))
    }

    func testTheLoaderAcceptsAUsableSecretReferenceKey() throws {
        XCTAssertEqual(try decodeSecretReference(key: "subscription/sanitized").key, "subscription/sanitized")
        let atLimit = String(repeating: "k", count: SecretReference.maximumKeyBytes)
        XCTAssertEqual(try decodeSecretReference(key: atLimit).key, atLimit)
    }

    func testTheLoaderRefusesAnUnusableSecretReferenceKey() throws {
        // The loader refuses as well as the validator, so a caller that decodes
        // without validating still cannot end up holding an unusable key.
        for (label, key) in [
            ("empty", ""),
            ("space", "subscription/ sanitized"),
            ("newline", "subscription\nsanitized"),
            ("non-ascii", "server/credential-\u{2705}"),
            ("oversized", String(repeating: "k", count: SecretReference.maximumKeyBytes + 1)),
        ] {
            XCTAssertThrowsError(
                try decodeSecretReference(key: key),
                "the loader must refuse a secret reference key that is \(label)"
            )
        }
    }
}

/// The two redactors in this repository disagreed about the port: the config model
/// dropped it and the subscription redactor kept it, so the persisted display value
/// depended on which path had produced it. These cases pin the shared form.
final class RedactedURLFormTests: XCTestCase {
    func test_a_port_survives_redaction() {
        let source = SubscriptionSource(kind: .url, displayValue: "https://server.example:8443/secret-path")
        XCTAssertEqual(source.displayValue, "https://server.example:8443/••••••••")
    }

    func test_no_port_stays_no_port() {
        let source = SubscriptionSource(kind: .url, displayValue: "https://server.example/secret-path")
        XCTAssertEqual(source.displayValue, "https://server.example/••••••••")
    }

    func test_a_url_with_userinfo_is_refused_outright() {
        // The whole value falls back to the literal "redacted", so neither the
        // host nor anything from the userinfo survives — and in particular the
        // colon in "user:pa55word" cannot be mistaken for a port. This is stricter
        // than the subscription redactor, which keeps scheme and host; it is
        // recorded here rather than reconciled, because the config path is the one
        // that reads a file an operator edited by hand.
        let source = SubscriptionSource(
            kind: .url,
            displayValue: "https://user:pa55word@server.example:8443/secret-path"
        )
        XCTAssertEqual(source.displayValue, "redacted")
    }

    func test_the_redacted_form_validates_as_sanitized() {
        for value in [
            "https://server.example/••••••••",
            "https://server.example:8443/••••••••",
        ] {
            let source = SubscriptionSource(kind: .url, displayValue: value)
            XCTAssertTrue(
                SubscriptionSource.isSanitizedURLDisplayValue(source.displayValue),
                "\(source.displayValue) is not recognised as its own redacted form"
            )
        }
    }
}
