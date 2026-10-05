import Foundation
import XCTest
@testable import RoviaConfig
@testable import RoviaRouting

/// Coverage of the selection model's convenience initializers, compatibility
/// aliases, Codable shapes, and the evaluator's convenience overloads and
/// freshness edges.
final class ServerSelectionAPITests: XCTestCase {
    private let groupID = UUID(uuidString: "00000000-0000-0000-0000-000000000501")!
    private let firstServerID = UUID(uuidString: "00000000-0000-0000-0000-000000000502")!
    private let secondServerID = UUID(uuidString: "00000000-0000-0000-0000-000000000503")!
    private let thirdServerID = UUID(uuidString: "00000000-0000-0000-0000-000000000504")!

    // MARK: - health sample conveniences

    func testHealthSampleConvenienceInitializersAndAliases() {
        let now = Date(timeIntervalSince1970: 10_000)
        let byTimestamp = HealthSample(serverID: firstServerID, timestamp: now, latency: 12, healthy: false)
        let byMilliseconds = HealthSample(
            serverID: firstServerID,
            observedAt: now,
            latencyMilliseconds: 34,
            succeeded: true
        )

        XCTAssertEqual(byTimestamp.observedAt, now)
        XCTAssertEqual(byTimestamp.latency, 12)
        XCTAssertFalse(byTimestamp.isHealthy)

        XCTAssertEqual(byMilliseconds.latency, 34)
        XCTAssertTrue(byMilliseconds.isHealthy)

        XCTAssertEqual(byMilliseconds.timestamp, now)
        XCTAssertEqual(byMilliseconds.measuredAt, now)
        XCTAssertTrue(byMilliseconds.healthy)
        XCTAssertTrue(byMilliseconds.succeeded)
        XCTAssertEqual(byMilliseconds.latencyMilliseconds, 34)
        XCTAssertTrue(byMilliseconds.isAvailable)

        let withoutLatency = HealthSample(serverID: firstServerID, observedAt: now, latency: nil, isHealthy: true)
        XCTAssertNil(withoutLatency.latencyMilliseconds)
    }

    func testHealthSampleEncodingKeepsTheLatencyExplicit() throws {
        let now = Date(timeIntervalSince1970: 10_000)
        let withLatency = HealthSample(serverID: firstServerID, observedAt: now, latency: 12, isHealthy: true)
        let withoutLatency = HealthSample(serverID: firstServerID, observedAt: now, latency: nil, isHealthy: false)

        let withData = try JSONCoding.encoder().encode(withLatency)
        let withoutData = try JSONCoding.encoder().encode(withoutLatency)

        XCTAssertTrue(String(decoding: withData, as: UTF8.self).contains("\"latency\":12"))
        XCTAssertTrue(String(decoding: withoutData, as: UTF8.self).contains("\"latency\":null"))
        XCTAssertEqual(try JSONCoding.decoder().decode(HealthSample.self, from: withData), withLatency)
        XCTAssertEqual(try JSONCoding.decoder().decode(HealthSample.self, from: withoutData), withoutLatency)
    }

    func testHealthSampleDecodingRejectsUnknownFields() {
        let data = Data(
            """
            {"serverID":"00000000-0000-0000-0000-000000000502","observedAt":"1970-01-01T02:46:40Z","latency":null,"isHealthy":true,"unexpected":true}
            """.utf8
        )

        XCTAssertThrowsError(try JSONCoding.decoder().decode(HealthSample.self, from: data))
    }

    // MARK: - health snapshot conveniences

    func testHealthSnapshotConvenienceInitializersAndAliases() {
        let now = Date(timeIntervalSince1970: 10_000)
        let first = HealthSample(serverID: firstServerID, observedAt: now, latency: 10, isHealthy: true)
        let second = HealthSample(serverID: secondServerID, observedAt: now, latency: 20, isHealthy: true)
        let byID = [secondServerID: second, firstServerID: first]

        XCTAssertEqual(
            HealthSnapshot(capturedAt: now, samples: byID).samples,
            [first, second],
            "dictionary initializers must order samples by server ID for determinism"
        )
        XCTAssertEqual(HealthSnapshot(timestamp: now, samples: [first]).capturedAt, now)
        XCTAssertEqual(HealthSnapshot(observedAt: now, samples: [first]).capturedAt, now)
        XCTAssertEqual(HealthSnapshot(samples: [first], capturedAt: now).samples, [first])
        XCTAssertEqual(HealthSnapshot(samples: byID, capturedAt: now).samples, [first, second])
        XCTAssertEqual(HealthSnapshot(observedAt: now, samples: byID).samples, [first, second])
        XCTAssertEqual(HealthSnapshot(timestamp: now, samples: byID).samples, [first, second])

        let snapshot = HealthSnapshot(capturedAt: now, samples: [first, second])
        XCTAssertEqual(snapshot.timestamp, now)
        XCTAssertEqual(snapshot.observedAt, now)
        XCTAssertEqual(snapshot.observations, [first, second])
        XCTAssertEqual(snapshot.values, [first, second])
        XCTAssertEqual(snapshot[firstServerID], first)
        XCTAssertNil(snapshot[thirdServerID])
    }

    func testHealthSnapshotCodableRoundTrip() throws {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [HealthSample(serverID: firstServerID, observedAt: now, latency: 10, isHealthy: true)]
        )

        let data = try JSONCoding.encoder().encode(snapshot)

        XCTAssertEqual(try JSONCoding.decoder().decode(HealthSnapshot.self, from: data), snapshot)
    }

    func testHealthSnapshotDecodingRejectsUnknownFields() {
        let data = Data(
            "{\"capturedAt\":\"1970-01-01T02:46:40Z\",\"samples\":[],\"unexpected\":true}".utf8
        )

        XCTAssertThrowsError(try JSONCoding.decoder().decode(HealthSnapshot.self, from: data))
    }

    // MARK: - duplicate sample preference edges

    func testNewerSampleWinsRegardlessOfLatency() {
        let now = Date(timeIntervalSince1970: 10_000)
        let older = HealthSample(serverID: firstServerID, observedAt: now - 10, latency: 1, isHealthy: true)
        let newer = HealthSample(serverID: firstServerID, observedAt: now, latency: 50, isHealthy: true)

        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [older, newer]).sample(for: firstServerID), newer)
        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [newer, older]).sample(for: firstServerID), newer)
    }

    func testEqualTimeSamplesPreferAValidLatencyOverAMissingOne() {
        let now = Date(timeIntervalSince1970: 10_000)
        let missing = HealthSample(serverID: firstServerID, observedAt: now, latency: nil, isHealthy: true)
        let measured = HealthSample(serverID: firstServerID, observedAt: now, latency: 30, isHealthy: true)

        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [missing, measured]).sample(for: firstServerID), measured)
        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [measured, missing]).sample(for: firstServerID), measured)
    }

    func testEqualTimeSamplesWithTwoMissingLatenciesKeepTheFirst() {
        let now = Date(timeIntervalSince1970: 10_000)
        let first = HealthSample(serverID: firstServerID, observedAt: now, latency: nil, isHealthy: true)
        let second = HealthSample(serverID: firstServerID, observedAt: now, latency: nil, isHealthy: true)

        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [first, second]).sample(for: firstServerID), first)
    }

    func testEqualTimeSamplesPreferAMissingLatencyOverANegativeOne() {
        let now = Date(timeIntervalSince1970: 10_000)
        let negative = HealthSample(serverID: firstServerID, observedAt: now, latency: -5, isHealthy: true)
        let missing = HealthSample(serverID: firstServerID, observedAt: now, latency: nil, isHealthy: true)

        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [negative, missing]).sample(for: firstServerID), missing)
        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [missing, negative]).sample(for: firstServerID), missing)
    }

    func testEqualTimeNonFiniteLatenciesBreakTheTieByBitPattern() {
        let now = Date(timeIntervalSince1970: 10_000)
        let infinity = HealthSample(serverID: firstServerID, observedAt: now, latency: .infinity, isHealthy: true)
        let nan = HealthSample(serverID: firstServerID, observedAt: now, latency: .nan, isHealthy: true)

        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [nan, infinity]).sample(for: firstServerID), infinity)
        XCTAssertEqual(HealthSnapshot(capturedAt: now, samples: [infinity, nan]).sample(for: firstServerID), infinity)
    }

    // MARK: - selection request conveniences

    func testServerSelectionRequestConvenienceInitializersAndAliases() {
        let now = Date(timeIntervalSince1970: 10_000)
        let group = makeGroup(mode: .manual, policy: .manual)
        let snapshot = HealthSnapshot(capturedAt: now)

        let byHealthSnapshot = ServerSelectionRequest(
            group: group,
            healthSnapshot: snapshot,
            now: now,
            requestedServerID: secondServerID,
            staleAfter: 30
        )
        XCTAssertEqual(byHealthSnapshot.requestedServerID, secondServerID)
        XCTAssertEqual(byHealthSnapshot.staleAfter, 30)

        let bySnapshot = ServerSelectionRequest(
            group: group,
            selectedServerID: secondServerID,
            snapshot: snapshot,
            now: now,
            staleAfter: 30
        )
        XCTAssertEqual(bySnapshot.requestedServerID, secondServerID)
        XCTAssertEqual(bySnapshot.healthSnapshot, snapshot)

        let bySelectedAndHealth = ServerSelectionRequest(
            group: group,
            selectedServerID: secondServerID,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: 30
        )
        XCTAssertEqual(bySelectedAndHealth, byHealthSnapshot)

        XCTAssertEqual(byHealthSnapshot.selectedServerID, secondServerID)
        XCTAssertEqual(byHealthSnapshot.manualServerID, secondServerID)
        XCTAssertEqual(byHealthSnapshot.manualSelectionID, secondServerID)
        XCTAssertEqual(byHealthSnapshot.health, snapshot)
        XCTAssertEqual(byHealthSnapshot.currentTime, now)
        XCTAssertEqual(byHealthSnapshot.maximumSampleAge, 30)
    }

    func testServerSelectionRequestCodableRoundTripKeepsNullablesExplicit() throws {
        let now = Date(timeIntervalSince1970: 10_000)
        let group = makeGroup(mode: .manual, policy: .manual)
        let snapshot = HealthSnapshot(capturedAt: now)

        let full = ServerSelectionRequest(
            group: group,
            requestedServerID: secondServerID,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: 30
        )
        let fullData = try JSONCoding.encoder().encode(full)
        let fullJSON = String(decoding: fullData, as: UTF8.self)
        XCTAssertTrue(fullJSON.contains("\"requestedServerID\":\"\(secondServerID.uuidString)\""))
        XCTAssertTrue(fullJSON.contains("\"staleAfter\":30"))
        XCTAssertEqual(try JSONCoding.decoder().decode(ServerSelectionRequest.self, from: fullData), full)

        let minimal = ServerSelectionRequest(group: group, requestedServerID: nil, healthSnapshot: snapshot, now: now)
        let minimalData = try JSONCoding.encoder().encode(minimal)
        let minimalJSON = String(decoding: minimalData, as: UTF8.self)
        XCTAssertTrue(minimalJSON.contains("\"requestedServerID\":null"))
        XCTAssertTrue(minimalJSON.contains("\"staleAfter\":null"))
        XCTAssertEqual(try JSONCoding.decoder().decode(ServerSelectionRequest.self, from: minimalData), minimal)
    }

    func testServerSelectionRequestDecodingRejectsUnknownFields() throws {
        let now = Date(timeIntervalSince1970: 10_000)
        let minimal = ServerSelectionRequest(
            group: makeGroup(mode: .manual, policy: .manual),
            requestedServerID: nil,
            healthSnapshot: HealthSnapshot(capturedAt: now),
            now: now
        )
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONCoding.encoder().encode(minimal)) as? [String: Any]
        )
        object["unexpected"] = true
        let data = try JSONSerialization.data(withJSONObject: object)

        XCTAssertThrowsError(try JSONCoding.decoder().decode(ServerSelectionRequest.self, from: data))
    }

    // MARK: - selection decision API

    func testReasonCodeCompatibilityAliases() {
        XCTAssertEqual(GroupSelectionReasonCode.notMember, .requestedServerNotMember)
        XCTAssertEqual(GroupSelectionReasonCode.noCandidate, .noHealthyCandidate)
    }

    func testDecisionInitFallsBackToNoCandidateForAnUnknownReasonCode() {
        let decision = GroupSelectionDecision(
            groupID: groupID,
            policy: .manual,
            selectedServerID: nil,
            reasonCode: "bogus"
        )

        XCTAssertEqual(decision.reasonCode, "noHealthyCandidate")
        XCTAssertEqual(decision.reasonValue, .noHealthyCandidate)
    }

    func testDecisionAliasesAndEncodingWithASelectedServer() throws {
        let decision = GroupSelectionDecision(
            groupID: groupID,
            policy: .manual,
            selectedServerID: secondServerID,
            reasonCode: "selected"
        )

        XCTAssertEqual(decision.selectedServer, secondServerID)
        XCTAssertEqual(decision.serverID, secondServerID)
        XCTAssertEqual(decision.reason, "selected")
        XCTAssertEqual(decision.outcome, "selected")
        XCTAssertTrue(decision.hasSelection)
        XCTAssertFalse(decision.noCandidate)
        XCTAssertEqual(decision.reasonValue, .selected)

        let data = try JSONCoding.encoder().encode(decision)
        let json = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(json.contains("\"selectedServerID\":\"\(secondServerID.uuidString)\""))
        XCTAssertEqual(try JSONCoding.decoder().decode(GroupSelectionDecision.self, from: data), decision)
    }

    func testDecisionDecodingRejectsAnUnknownReasonCode() {
        let data = Data(
            """
            {"groupID":"00000000-0000-0000-0000-000000000501","policy":"manual","selectedServerID":null,"reasonCode":"bogus"}
            """.utf8
        )

        XCTAssertThrowsError(try JSONCoding.decoder().decode(GroupSelectionDecision.self, from: data))
    }

    func testDecisionDecodingRejectsUnknownFields() {
        let data = Data(
            """
            {"groupID":"00000000-0000-0000-0000-000000000501","policy":"manual","selectedServerID":null,"reasonCode":"selected","unexpected":true}
            """.utf8
        )

        XCTAssertThrowsError(try JSONCoding.decoder().decode(GroupSelectionDecision.self, from: data))
    }

    // MARK: - evaluator convenience overloads

    func testEverySelectOverloadMatchesTheRequestBasedEntryPoint() {
        let now = Date(timeIntervalSince1970: 10_000)
        let group = makeGroup(mode: .manual, policy: .manual)
        let snapshot = HealthSnapshot(capturedAt: now)
        let evaluator = ServerSelectionEvaluator()
        let expected = evaluator.select(
            ServerSelectionRequest(
                group: group,
                requestedServerID: secondServerID,
                healthSnapshot: snapshot,
                now: now,
                staleAfter: 60
            )
        )
        let unrequested = evaluator.select(
            ServerSelectionRequest(group: group, requestedServerID: nil, healthSnapshot: snapshot, now: now, staleAfter: 60)
        )

        XCTAssertEqual(
            evaluator.select(group, requestedServerID: secondServerID, healthSnapshot: snapshot, now: now, staleAfter: 60),
            expected
        )
        XCTAssertEqual(
            evaluator.select(group, healthSnapshot: snapshot, now: now, staleAfter: 60),
            unrequested
        )
        XCTAssertEqual(
            evaluator.select(group, snapshot: snapshot, now: now, staleAfter: 60),
            unrequested
        )
        XCTAssertEqual(
            evaluator.select(group, requestedServerID: secondServerID, snapshot: snapshot, now: now, staleAfter: 60),
            expected
        )
        XCTAssertEqual(
            evaluator.select(group: group, requestedServerID: secondServerID, healthSnapshot: snapshot, now: now, staleAfter: 60),
            expected
        )
        XCTAssertEqual(
            evaluator.select(group: group, requestedServerID: secondServerID, health: snapshot, now: now, staleAfter: 60),
            expected
        )
        XCTAssertEqual(
            evaluator.select(group: group, health: snapshot, now: now, staleAfter: 60),
            unrequested
        )
    }

    // MARK: - freshness edges

    func testLowestLatencyWithOnlyStaleSamplesReportsStaleness() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(serverID: firstServerID, observedAt: now - 120, latency: 10, isHealthy: true),
                HealthSample(serverID: secondServerID, observedAt: now - 200, latency: 20, isHealthy: true)
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
        XCTAssertEqual(decision.reasonCode, "staleHealthSample")
    }

    func testLowestLatencyWithBothStaleAndInvalidSamplesReportsNoHealthyCandidate() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(serverID: firstServerID, observedAt: now - 120, latency: 10, isHealthy: true),
                HealthSample(serverID: secondServerID, observedAt: now, latency: -5, isHealthy: true)
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
        XCTAssertEqual(decision.reasonCode, "noHealthyCandidate")
    }

    func testLowestLatencyWithoutAnySamplesReportsNoHealthyCandidate() {
        let now = Date(timeIntervalSince1970: 10_000)
        let request = ServerSelectionRequest(
            group: makeGroup(mode: .lowestLatency, policy: .lowestLatency),
            requestedServerID: nil,
            healthSnapshot: HealthSnapshot(capturedAt: now),
            now: now,
            staleAfter: 60
        )

        let decision = ServerSelectionEvaluator().select(request)

        XCTAssertNil(decision.selectedServerID)
        XCTAssertEqual(decision.reasonCode, "noHealthyCandidate")
    }

    func testFailoverWithOnlyStaleSamplesReportsStaleness() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [
                HealthSample(serverID: firstServerID, observedAt: now - 120, latency: 10, isHealthy: true),
                HealthSample(serverID: secondServerID, observedAt: now - 200, latency: 20, isHealthy: true),
                HealthSample(serverID: thirdServerID, observedAt: now - 300, latency: 30, isHealthy: true)
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
        XCTAssertEqual(decision.reasonCode, "staleHealthSample")
    }

    func testAnUnboundedOrNegativeStalenessWindowTreatsEverySampleAsStale() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [firstServerID, secondServerID, thirdServerID].map {
                HealthSample(serverID: $0, observedAt: now, latency: 10, isHealthy: true)
            }
        )
        let group = makeGroup(mode: .failover, policy: .failover)

        for window in [TimeInterval.infinity, -1] {
            let request = ServerSelectionRequest(
                group: group,
                requestedServerID: nil,
                healthSnapshot: snapshot,
                now: now,
                staleAfter: window
            )

            let decision = ServerSelectionEvaluator().select(request)

            XCTAssertNil(decision.selectedServerID)
            XCTAssertEqual(decision.reasonCode, "staleHealthSample")
        }
    }

    func testAFutureSampleIsNotFresh() {
        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [firstServerID, secondServerID, thirdServerID].map {
                HealthSample(serverID: $0, observedAt: now + 10, latency: 10, isHealthy: true)
            }
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
        XCTAssertEqual(decision.reasonCode, "staleHealthSample")
    }

    func testTheEvaluatorStalenessDefaultAppliesWhenTheRequestOmitsIt() {
        XCTAssertEqual(ServerSelectionEvaluator.defaultStaleAfter, 300)

        let now = Date(timeIntervalSince1970: 10_000)
        let snapshot = HealthSnapshot(
            capturedAt: now,
            samples: [firstServerID, secondServerID, thirdServerID].map {
                HealthSample(serverID: $0, observedAt: now - 20, latency: 10, isHealthy: true)
            }
        )
        let group = makeGroup(mode: .failover, policy: .failover)
        let request = ServerSelectionRequest(group: group, requestedServerID: nil, healthSnapshot: snapshot, now: now)

        XCTAssertEqual(ServerSelectionEvaluator().select(request).selectedServerID, firstServerID)
        XCTAssertEqual(ServerSelectionEvaluator(staleAfter: 10).select(request).reasonCode, "staleHealthSample")
    }

    // MARK: - helpers

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
