import Foundation
import XCTest
@testable import RoviaConfig
@testable import RoviaRouting

final class ServerSelectionEvaluatorTests: XCTestCase {
    private let groupID = UUID(uuidString: "00000000-0000-0000-0000-000000000501")!
    private let firstServerID = UUID(uuidString: "00000000-0000-0000-0000-000000000502")!
    private let secondServerID = UUID(uuidString: "00000000-0000-0000-0000-000000000503")!
    private let thirdServerID = UUID(uuidString: "00000000-0000-0000-0000-000000000504")!
    private let outsiderID = UUID(uuidString: "00000000-0000-0000-0000-000000000505")!

    func testManualSelectionRejectsNonMember() {
        let now = Date(timeIntervalSince1970: 10_000)
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .manual, policy: .manual),
            requestedServerID: outsiderID,
            healthSnapshot: HealthSnapshot(capturedAt: now),
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertNil(decision.selectedServerID)
        XCTAssertFalse(decision.isSelected)
        XCTAssertEqual(decision.reasonCode, "requestedServerNotMember")
    }

    func testManualSelectionChoosesRequestedMemberWithoutUsingAnUnrequestedFallback() {
        let now = Date(timeIntervalSince1970: 10_000)
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .manual, policy: .manual),
            requestedServerID: secondServerID,
            healthSnapshot: HealthSnapshot(capturedAt: now),
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertEqual(decision.selectedServerID, secondServerID)
        XCTAssertTrue(decision.isSelected)
        XCTAssertEqual(decision.reasonCode, "selected")
    }

    func testManualSelectionRequiresARequestedMember() {
        let now = Date(timeIntervalSince1970: 10_000)
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .manual, policy: .manual),
            requestedServerID: nil,
            healthSnapshot: HealthSnapshot(capturedAt: now),
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertNil(decision.selectedServerID)
        XCTAssertEqual(decision.reasonCode, "manualSelectionRequired")
    }

    func testLowestLatencyIgnoresUnhealthyInvalidAndStaleSamples() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(
                    serverID: firstServerID,
                    observedAt: now.addingTimeInterval(-5),
                    latency: 50,
                    isHealthy: true
                ),
                HealthSample(
                    serverID: secondServerID,
                    observedAt: now.addingTimeInterval(-5),
                    latency: 10,
                    isHealthy: false
                ),
                HealthSample(
                    serverID: thirdServerID,
                    observedAt: now.addingTimeInterval(-120),
                    latency: 1,
                    isHealthy: true
                )
            ]
        )
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .lowestLatency, policy: .lowestLatency),
            requestedServerID: nil,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertEqual(decision.selectedServerID, firstServerID)
        XCTAssertEqual(decision.reasonCode, "selected")
    }

    func testNegativeZeroLatencyNormalizesToPositiveZero() {
        let now = Date(timeIntervalSince1970: 10_000)
        let negativeZero = HealthSample(
            serverID: firstServerID,
            observedAt: now,
            latency: -0.0,
            isHealthy: true
        )
        let positiveZero = HealthSample(
            serverID: firstServerID,
            observedAt: now,
            latency: 0.0,
            isHealthy: true
        )
        let firstOrder = HealthSnapshot(capturedAt: now, samples: [negativeZero, positiveZero])
        let secondOrder = HealthSnapshot(capturedAt: now, samples: [positiveZero, negativeZero])

        XCTAssertEqual(negativeZero.latency?.bitPattern, 0.0.bitPattern)
        XCTAssertEqual(firstOrder.sample(for: firstServerID)?.latency?.bitPattern, 0.0.bitPattern)
        XCTAssertEqual(secondOrder.sample(for: firstServerID)?.latency?.bitPattern, 0.0.bitPattern)
    }

    func testDecodedNegativeZeroLatencyIsNormalizedAndSelectionIsOrderIndependent() throws {
        let timestamp = ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: 10_000))
        let negativeSample = """
        {"serverID":"00000000-0000-0000-0000-000000000502","observedAt":"\(timestamp)","latency":-0.0,"isHealthy":true}
        """
        let positiveSample = """
        {"serverID":"00000000-0000-0000-0000-000000000502","observedAt":"\(timestamp)","latency":0.0,"isHealthy":true}
        """

        let sample = try JSONCoding.decoder().decode(HealthSample.self, from: Data(negativeSample.utf8))
        XCTAssertEqual(sample.latency?.bitPattern, 0.0.bitPattern)

        func snapshotData(_ samples: [String]) -> Data {
            Data("{\"capturedAt\":\"\(timestamp)\",\"samples\":[\(samples.joined(separator: ","))]}".utf8)
        }

        let first = try JSONCoding.decoder().decode(
            HealthSnapshot.self,
            from: snapshotData([negativeSample, positiveSample])
        )
        let second = try JSONCoding.decoder().decode(
            HealthSnapshot.self,
            from: snapshotData([positiveSample, negativeSample])
        )

        XCTAssertEqual(first.sample(for: firstServerID)?.latency?.bitPattern, 0.0.bitPattern)
        XCTAssertEqual(second.sample(for: firstServerID)?.latency?.bitPattern, 0.0.bitPattern)
        XCTAssertEqual(first.sample(for: firstServerID), second.sample(for: firstServerID))
    }

    func testLowestLatencyRejectsNonFiniteAndNegativeValues() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(
                    serverID: firstServerID,
                    observedAt: now,
                    latency: -1,
                    isHealthy: true
                ),
                HealthSample(
                    serverID: secondServerID,
                    observedAt: now,
                    latency: .nan,
                    isHealthy: true
                ),
                HealthSample(
                    serverID: thirdServerID,
                    observedAt: now,
                    latency: .infinity,
                    isHealthy: true
                )
            ]
        )
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .lowestLatency, policy: .lowestLatency),
            requestedServerID: nil,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertNil(decision.selectedServerID)
        XCTAssertFalse(decision.isSelected)
        XCTAssertEqual(decision.reasonCode, "noValidLatency")
    }

    func testLowestLatencyBreaksTiesUsingMemberOrder() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(
                    serverID: firstServerID,
                    observedAt: now,
                    latency: 20,
                    isHealthy: true
                ),
                HealthSample(
                    serverID: secondServerID,
                    observedAt: now,
                    latency: 20,
                    isHealthy: true
                )
            ]
        )
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .lowestLatency, policy: .lowestLatency),
            requestedServerID: nil,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: 60
        )

        let first = ServerSelectionEvaluator().select(request)
        let second = ServerSelectionEvaluator().select(request)

        XCTAssertEqual(first.selectedServerID, firstServerID)
        XCTAssertEqual(first, second)
    }

    func testFailoverPreservesMemberOrder() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(
                    serverID: firstServerID,
                    observedAt: now,
                    latency: 90,
                    isHealthy: false
                ),
                HealthSample(
                    serverID: secondServerID,
                    observedAt: now,
                    latency: 80,
                    isHealthy: true
                ),
                HealthSample(
                    serverID: thirdServerID,
                    observedAt: now,
                    latency: 10,
                    isHealthy: true
                )
            ]
        )
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .failover, policy: .failover),
            requestedServerID: nil,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertEqual(decision.selectedServerID, secondServerID)
        XCTAssertEqual(decision.reasonCode, "selected")
    }

    func testStaleSamplesAreExcludedAtTheInjectedDeadline() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(
                    serverID: firstServerID,
                    observedAt: now.addingTimeInterval(-61),
                    latency: 1,
                    isHealthy: true
                ),
                HealthSample(
                    serverID: secondServerID,
                    observedAt: now.addingTimeInterval(-60),
                    latency: 20,
                    isHealthy: true
                )
            ]
        )
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .lowestLatency, policy: .lowestLatency),
            requestedServerID: nil,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertEqual(decision.selectedServerID, secondServerID)
    }

    func testAllUnhealthyOrStaleMembersReturnExplicitNoCandidate() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(
                    serverID: firstServerID,
                    observedAt: now.addingTimeInterval(-1),
                    latency: 1,
                    isHealthy: false
                ),
                HealthSample(
                    serverID: secondServerID,
                    observedAt: now.addingTimeInterval(-61),
                    latency: 2,
                    isHealthy: true
                )
            ]
        )
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .failover, policy: .failover),
            requestedServerID: nil,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertNil(decision.selectedServerID)
        XCTAssertEqual(decision.reasonCode, "noHealthyCandidate")
        XCTAssertNil(decision.fallbackServerID)
    }

    func testEmptyGroupReturnsExplicitNoCandidate() {
        let now = Date(timeIntervalSince1970: 10_000)
        let group = ServerGroup(
            id: groupID,
            name: "Empty",
            mode: .lowestLatency,
            members: [],
            selectionPolicy: .lowestLatency
        )
        let request = ServerSelectionRequest(
            group: group,
            requestedServerID: nil,
            healthSnapshot: HealthSnapshot(capturedAt: now),
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertNil(decision.selectedServerID)
        XCTAssertEqual(decision.reasonCode, "emptyGroup")
    }

    func testSelectionDecisionIsCodableWithoutHealthOrDirectFallbackData() throws {
        let now = Date(timeIntervalSince1970: 10_000)
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .failover, policy: .failover),
            requestedServerID: nil,
            healthSnapshot: HealthSnapshot(capturedAt: now),
            now: now,
            staleAfter: 60
        )
        let decision = ServerSelectionEvaluator().select(request)
        let data = try JSONCoding.encoder().encode(decision)
        let json = String(decoding: data, as: UTF8.self)
        let decoded = try JSONCoding.decoder().decode(GroupSelectionDecision.self, from: data)

        XCTAssertEqual(decoded, decision)
        XCTAssertFalse(json.contains("direct"))
        XCTAssertFalse(json.lowercased().contains("credential"))
        XCTAssertFalse(json.lowercased().contains("endpoint"))
    }

    func testEqualTimeDuplicateSamplesUseStableCanonicalTieRule() {
        let now = Date(timeIntervalSince1970: 10_000)
        let healthy = HealthSample(
            serverID: firstServerID,
            observedAt: now,
            latency: 20,
            isHealthy: true
        )
        let unhealthy = HealthSample(
            serverID: firstServerID,
            observedAt: now,
            latency: 1,
            isHealthy: false
        )
        let firstOrder = HealthSnapshot(capturedAt: now, samples: [unhealthy, healthy])
        let secondOrder = HealthSnapshot(capturedAt: now, samples: [healthy, unhealthy])

        XCTAssertEqual(firstOrder.sample(for: firstServerID), healthy)
        XCTAssertEqual(secondOrder.sample(for: firstServerID), healthy)

        let lowerLatency = HealthSample(
            serverID: firstServerID,
            observedAt: now,
            latency: 5,
            isHealthy: true
        )
        let higherLatency = HealthSample(
            serverID: firstServerID,
            observedAt: now,
            latency: 20,
            isHealthy: true
        )
        let latencyFirst = HealthSnapshot(capturedAt: now, samples: [higherLatency, lowerLatency])
        let latencySecond = HealthSnapshot(capturedAt: now, samples: [lowerLatency, higherLatency])

        XCTAssertEqual(latencyFirst.sample(for: firstServerID), lowerLatency)
        XCTAssertEqual(latencySecond.sample(for: firstServerID), lowerLatency)
    }

    private func makeGroup(mode: GroupMode, policy: SelectionPolicy) -> ServerGroup {
        ServerGroup(
            id: groupID,
            name: "Test",
            mode: mode,
            members: [firstServerID, secondServerID, thirdServerID],
            selectionPolicy: policy
        )
    }
}
