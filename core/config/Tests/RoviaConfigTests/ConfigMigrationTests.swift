import Foundation
import XCTest
@testable import RoviaConfig

final class ConfigMigrationTests: XCTestCase {
    func testCurrentSchemaVersionIsOne() {
        XCTAssertEqual(CanonicalConfigLoader.currentSchemaVersion, 1)
    }

    func testLoaderRejectsUnsupportedFutureVersionFixtureShape() throws {
        let data = try fixtureData("unsupported-version.json")

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data)) { error in
            XCTAssertEqual(error as? CanonicalConfigError, .invalidSchemaVersion(2))
        }
    }

    func testLoaderRejectsNonPositiveSchemaVersion() throws {
        XCTAssertThrowsError(try CanonicalConfigLoader.load(unsupportedConfigData(version: 0)))
        XCTAssertThrowsError(try CanonicalConfigLoader.load(unsupportedConfigData(version: -1)))
    }

    func testMigrationBoundaryAcceptsOnlyCurrentVersion() throws {
        let current = try minimalConfigData()

        XCTAssertEqual(try CanonicalConfigLoader.migrate(current), current)
        XCTAssertThrowsError(try CanonicalConfigLoader.migrate(unsupportedConfigData(version: 2)))
    }

    func testLoaderValidatesCurrentMinimalConfiguration() throws {
        let config = try CanonicalConfigLoader.load(minimalConfigData())

        XCTAssertEqual(config.schemaVersion, 1)
        XCTAssertTrue(config.validationReport().isValid)
    }

    func testSecretBearingTransportFixtureFailsWithoutEchoingCanary() throws {
        let data = try fixtureData("secret-bearing-transport.json")

        XCTAssertThrowsError(try CanonicalConfigLoader.load(data)) { error in
            XCTAssertFalse(String(describing: error).contains("transport-secret-canary"))
        }
    }

    private func minimalConfigData() throws -> Data {
        try fixtureData("minimal.json")
    }

    private func fixtureData(_ name: String) throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/config")
            .appendingPathComponent(name)
        return try Data(contentsOf: url)
    }

    private func unsupportedConfigData(version: Int) throws -> Data {
        var object = try JSONSerialization.jsonObject(
            with: try minimalConfigData()
        ) as? [String: Any] ?? [:]
        object["schemaVersion"] = version
        return try JSONSerialization.data(withJSONObject: object)
    }

}
