import XCTest
@testable import RoviaConfig
@testable import RoviaSubscription

final class SubscriptionModelsTests: XCTestCase {
    func testSourceDoesNotExposeCredentialInDisplayValue() throws {
        let source = SubscriptionSource(
            kind: .url,
            displayValue: "https://example.com/sub/secret-token?token=another-secret",
            secretReference: SecretReference(key: "subscription/example")
        )

        XCTAssertEqual(source.displayValue, "https://example.com/••••••••")
        let data = try JSONCoding.encoder().encode(source)
        let json = String(decoding: data, as: UTF8.self)

        XCTAssertTrue(json.contains("example.com"))
        XCTAssertFalse(json.contains("password"))
        XCTAssertTrue(json.contains("subscription/example"))
    }

    func testDecodedURLSourceIsRedacted() throws {
        let data = Data(
            """
             {
               "kind": "url",
               "displayValue": "https://example.com/sub/secret-token?token=another-secret",
               "secretReference": {
                 "kind": "keychain",
                 "key": "subscription/example"
               }
             }

            """.utf8
        )

        let source = try JSONCoding.decoder().decode(SubscriptionSource.self, from: data)

        XCTAssertEqual(source.displayValue, "https://example.com/••••••••")
    }

    func testSubscriptionInputRejectsOversizedData() {
        let data = Data(repeating: 0x61, count: SubscriptionLimits.maximumBytes + 1)

        XCTAssertThrowsError(try SubscriptionLimits.validate(data)) { error in
            XCTAssertEqual(error as? SubscriptionImportError, .inputTooLarge)
        }
    }

    func testRedactorRemovesURLPathAndQuery() {
        let redacted = SubscriptionRedactor.redactURL("https://example.com/sub/secret-token?token=another-secret")

        XCTAssertEqual(redacted, "https://example.com/••••••••")
    }
}

/// The config model and the subscription redactor used to disagree about the port:
/// this one kept it and that one dropped it, so the persisted display value
/// depended on which path had produced it. This suite can compare them directly
/// because RoviaSubscription depends on RoviaConfig, and it does, because a
/// divergence here is invisible to every other test in the repository.
final class RedactorAgreementTests: XCTestCase {
    private func configForm(_ value: String) -> String {
        SubscriptionSource(kind: .url, displayValue: value).displayValue
    }

    func test_both_redactors_agree_on_the_port() {
        for value in [
            "https://server.example/secret",
            "https://server.example:8443/secret",
            "http://server.example:80/secret",
            "http://server.example:8080/secret",
        ] {
            let config = configForm(value)
            let subscription = SubscriptionRedactor.redactURL(value)
            XCTAssertEqual(
                config,
                subscription,
                "the two redactors disagree about the same input: config wrote "
                + config + " and the subscription wrote " + subscription,
            )
        }
    }

    func test_the_shared_form_is_what_privacy_documents() {
        // PRIVACY.md states a redacted value keeps the scheme, host, and port.
        let redacted = configForm("https://server.example:8443/secret")
        XCTAssertEqual(redacted, "https://server.example:8443/••••••••")
        XCTAssertTrue(redacted.contains(":8443"), "the documented port did not survive")
    }
}
