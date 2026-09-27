import Foundation
import XCTest
@testable import RoviaConfig
@testable import RoviaEngineAPI

final class TunnelEngineTests: XCTestCase {
    func testCanonicalTunnelConfigurationPreservesSchemaVersion() throws {
        let configuration = CanonicalTunnelConfiguration(
            schemaVersion: 7,
            appConfig: AppConfig(
                schemaVersion: 7,
                subscriptions: [],
                groups: [],
                routing: RouteSet(rules: [], defaultAction: .direct),
                dns: DNSPolicy(mode: .system),
                privacy: PrivacyPolicy()
            )
        )

        XCTAssertEqual(configuration.schemaVersion, configuration.appConfig.schemaVersion)
    }

    func testValidationReportCanDescribeWarnings() {
        let report = ValidationReport(valid: true, warnings: ["engine not enabled"])

        XCTAssertTrue(report.valid)
        XCTAssertEqual(report.warnings, ["engine not enabled"])
    }

    func testRuntimeContextCarriesPreparedConfigurationAndPacketBridge() {
        let prepared = PreparedEngineConfiguration(engineID: "xray", opaquePayload: Data([1, 2, 3]))
        let context = TunnelRuntimeContext(
            sessionID: UUID(),
            platform: "test",
            preparedConfiguration: prepared,
            packetBridge: EmptyPacketBridge()
        )

        XCTAssertEqual(context.preparedConfiguration, prepared)
        XCTAssertTrue(context.packetBridge is EmptyPacketBridge)
    }
}

private struct EmptyPacketBridge: PacketBridge {
    func read() async throws -> [EnginePacket] {
        []
    }

    func write(_ packets: [EnginePacket]) async throws {}
}
