import Foundation
import RoviaConfig

public struct HealthSample: Codable, Sendable, Equatable {
    public let serverID: UUID
    public let observedAt: Date
    public let latency: TimeInterval?
    public let isHealthy: Bool

    public init(
        serverID: UUID,
        observedAt: Date,
        latency: TimeInterval? = nil,
        isHealthy: Bool = true
    ) {
        self.serverID = serverID
        self.observedAt = observedAt
        self.latency = Self.normalizedLatency(latency)
        self.isHealthy = isHealthy
    }

    public init(
        serverID: UUID,
        timestamp: Date,
        latency: TimeInterval? = nil,
        healthy: Bool
    ) {
        self.init(
            serverID: serverID,
            observedAt: timestamp,
            latency: latency,
            isHealthy: healthy
        )
    }

    public init(
        serverID: UUID,
        observedAt: Date,
        latencyMilliseconds: Double?,
        succeeded: Bool
    ) {
        self.init(
            serverID: serverID,
            observedAt: observedAt,
            latency: latencyMilliseconds,
            isHealthy: succeeded
        )
    }

    public var timestamp: Date { observedAt }
    public var measuredAt: Date { observedAt }
    public var healthy: Bool { isHealthy }
    public var succeeded: Bool { isHealthy }
    public var latencyMilliseconds: TimeInterval? { latency }
    public var isAvailable: Bool { isHealthy }

    public init(from decoder: Decoder) throws {
        try RoutingCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["serverID", "observedAt", "latency", "isHealthy"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serverID = try container.decode(UUID.self, forKey: .serverID)
        observedAt = try container.decode(Date.self, forKey: .observedAt)
        latency = Self.normalizedLatency(
            try container.decodeIfPresent(TimeInterval.self, forKey: .latency)
        )
        isHealthy = try container.decode(Bool.self, forKey: .isHealthy)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(serverID, forKey: .serverID)
        try container.encode(observedAt, forKey: .observedAt)
        if let latency {
            try container.encode(latency, forKey: .latency)
        } else {
            try container.encodeNil(forKey: .latency)
        }
        try container.encode(isHealthy, forKey: .isHealthy)
    }

    private static func normalizedLatency(_ latency: TimeInterval?) -> TimeInterval? {
        guard let latency, latency == 0 else { return latency }
        return 0.0
    }

    private enum CodingKeys: String, CodingKey {
        case serverID
        case observedAt
        case latency
        case isHealthy
    }
}

public struct HealthSnapshot: Codable, Sendable, Equatable {
    public static let equalTimeDuplicateSampleTieRule =
        "newest observedAt; equal time: healthy first, valid non-negative latency first, lower latency within a rank, then Double bitPattern"

    public let capturedAt: Date
    public let samples: [HealthSample]

    public init(capturedAt: Date, samples: [HealthSample] = []) {
        self.capturedAt = capturedAt
        self.samples = samples
    }

    public init(timestamp: Date, samples: [HealthSample] = []) {
        self.init(capturedAt: timestamp, samples: samples)
    }

    public init(observedAt: Date, samples: [HealthSample] = []) {
        self.init(capturedAt: observedAt, samples: samples)
    }

    public init(capturedAt: Date, samples: [UUID: HealthSample]) {
        self.init(
            capturedAt: capturedAt,
            samples: samples.values.sorted { $0.serverID.uuidString < $1.serverID.uuidString }
        )
    }

    public init(samples: [HealthSample], capturedAt: Date) {
        self.init(capturedAt: capturedAt, samples: samples)
    }

    public init(samples: [UUID: HealthSample], capturedAt: Date) {
        self.init(capturedAt: capturedAt, samples: samples)
    }

    public init(observedAt: Date, samples: [UUID: HealthSample]) {
        self.init(capturedAt: observedAt, samples: samples)
    }

    public init(timestamp: Date, samples: [UUID: HealthSample]) {
        self.init(capturedAt: timestamp, samples: samples)
    }

    public var timestamp: Date { capturedAt }
    public var observedAt: Date { capturedAt }
    public var observations: [HealthSample] { samples }
    public var values: [HealthSample] { samples }

    public func sample(for serverID: UUID) -> HealthSample? {
        var selected: HealthSample?
        for sample in samples where sample.serverID == serverID {
            if let current = selected, !Self.isPreferred(sample, over: current) {
                continue
            }
            selected = sample
        }
        return selected
    }

    private static func isPreferred(_ candidate: HealthSample, over current: HealthSample) -> Bool {
        if candidate.observedAt != current.observedAt {
            return candidate.observedAt > current.observedAt
        }
        if candidate.isHealthy != current.isHealthy {
            return candidate.isHealthy
        }

        let candidateRank = latencyRank(candidate.latency)
        let currentRank = latencyRank(current.latency)
        if candidateRank != currentRank {
            return candidateRank < currentRank
        }

        guard let candidateLatency = candidate.latency,
              let currentLatency = current.latency else {
            return false
        }
        if candidateLatency == currentLatency {
            return false
        }
        if candidateLatency.isFinite && currentLatency.isFinite {
            return candidateLatency < currentLatency
        }
        return candidateLatency.bitPattern < currentLatency.bitPattern
    }

    private static func latencyRank(_ latency: TimeInterval?) -> Int {
        guard let latency else { return 1 }
        guard latency.isFinite else { return 2 }
        return latency >= 0 ? 0 : 3
    }

    public subscript(serverID: UUID) -> HealthSample? {
        sample(for: serverID)
    }

    public init(from decoder: Decoder) throws {
        try RoutingCodingSupport.rejectUnknownKeys(decoder, allowed: ["capturedAt", "samples"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        capturedAt = try container.decode(Date.self, forKey: .capturedAt)
        samples = try container.decode([HealthSample].self, forKey: .samples)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(capturedAt, forKey: .capturedAt)
        try container.encode(samples, forKey: .samples)
    }

    private enum CodingKeys: String, CodingKey {
        case capturedAt
        case samples
    }
}

public struct ServerSelectionRequest: Codable, Sendable, Equatable {
    public let group: ServerGroup
    public let requestedServerID: UUID?
    public let healthSnapshot: HealthSnapshot
    public let now: Date
    public let staleAfter: TimeInterval?

    public init(
        group: ServerGroup,
        requestedServerID: UUID? = nil,
        healthSnapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) {
        self.group = group
        self.requestedServerID = requestedServerID
        self.healthSnapshot = healthSnapshot
        self.now = now
        self.staleAfter = staleAfter
    }

    public init(
        group: ServerGroup,
        healthSnapshot: HealthSnapshot,
        now: Date,
        requestedServerID: UUID? = nil,
        staleAfter: TimeInterval? = nil
    ) {
        self.init(
            group: group,
            requestedServerID: requestedServerID,
            healthSnapshot: healthSnapshot,
            now: now,
            staleAfter: staleAfter
        )
    }

    public init(
        group: ServerGroup,
        selectedServerID: UUID?,
        snapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) {
        self.init(
            group: group,
            requestedServerID: selectedServerID,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: staleAfter
        )
    }

    public init(
        group: ServerGroup,
        selectedServerID: UUID?,
        healthSnapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) {
        self.init(
            group: group,
            requestedServerID: selectedServerID,
            healthSnapshot: healthSnapshot,
            now: now,
            staleAfter: staleAfter
        )
    }

    public var selectedServerID: UUID? { requestedServerID }
    public var manualServerID: UUID? { requestedServerID }
    public var manualSelectionID: UUID? { requestedServerID }
    public var health: HealthSnapshot { healthSnapshot }
    public var currentTime: Date { now }
    public var maximumSampleAge: TimeInterval? { staleAfter }

    public init(from decoder: Decoder) throws {
        try RoutingCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["group", "requestedServerID", "healthSnapshot", "now", "staleAfter"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        group = try container.decode(ServerGroup.self, forKey: .group)
        requestedServerID = try container.decodeIfPresent(UUID.self, forKey: .requestedServerID)
        healthSnapshot = try container.decode(HealthSnapshot.self, forKey: .healthSnapshot)
        now = try container.decode(Date.self, forKey: .now)
        staleAfter = try container.decodeIfPresent(TimeInterval.self, forKey: .staleAfter)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(group, forKey: .group)
        if let requestedServerID {
            try container.encode(requestedServerID, forKey: .requestedServerID)
        } else {
            try container.encodeNil(forKey: .requestedServerID)
        }
        try container.encode(healthSnapshot, forKey: .healthSnapshot)
        try container.encode(now, forKey: .now)
        if let staleAfter {
            try container.encode(staleAfter, forKey: .staleAfter)
        } else {
            try container.encodeNil(forKey: .staleAfter)
        }
    }

    private enum CodingKeys: String, CodingKey {
        case group
        case requestedServerID
        case healthSnapshot
        case now
        case staleAfter
    }
}

public enum GroupSelectionReasonCode: String, Codable, Sendable, Equatable {
    case selected
    case emptyGroup
    case manualSelectionRequired
    case requestedServerNotMember
    case noHealthyCandidate
    case noValidLatency
    case staleHealthSample
    case invalidGroup

    public static var notMember: Self { .requestedServerNotMember }
    public static var noCandidate: Self { .noHealthyCandidate }
}

public struct GroupSelectionDecision: Codable, Sendable, Equatable {
    public let groupID: UUID
    public let policy: SelectionPolicy
    public let selectedServerID: UUID?
    public let reasonCode: String

    public init(
        groupID: UUID,
        policy: SelectionPolicy,
        selectedServerID: UUID?,
        reasonCode: String
    ) {
        self.groupID = groupID
        self.policy = policy
        self.selectedServerID = selectedServerID
        self.reasonCode = GroupSelectionReasonCode(rawValue: reasonCode)?.rawValue
            ?? GroupSelectionReasonCode.noHealthyCandidate.rawValue
    }

    public init(from decoder: Decoder) throws {
        try RoutingCodingSupport.rejectUnknownKeys(
            decoder,
            allowed: ["groupID", "policy", "selectedServerID", "reasonCode"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        groupID = try container.decode(UUID.self, forKey: .groupID)
        policy = try container.decode(SelectionPolicy.self, forKey: .policy)
        selectedServerID = try container.decode(UUID?.self, forKey: .selectedServerID)
        let value = try container.decode(String.self, forKey: .reasonCode)
        guard GroupSelectionReasonCode(rawValue: value) != nil else {
            throw DecodingError.dataCorruptedError(
                forKey: .reasonCode,
                in: container,
                debugDescription: "Unknown group selection reason code"
            )
        }
        reasonCode = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(groupID, forKey: .groupID)
        try container.encode(policy, forKey: .policy)
        if let selectedServerID {
            try container.encode(selectedServerID, forKey: .selectedServerID)
        } else {
            try container.encodeNil(forKey: .selectedServerID)
        }
        try container.encode(reasonCode, forKey: .reasonCode)
    }

    public var selectedServer: UUID? { selectedServerID }
    public var serverID: UUID? { selectedServerID }
    public var reason: String { reasonCode }
    public var outcome: String { reasonCode }
    public var isSelected: Bool { selectedServerID != nil }
    public var noCandidate: Bool { selectedServerID == nil }
    public var fallbackServerID: UUID? { nil }
    public var hasSelection: Bool { isSelected }
    public var reasonValue: GroupSelectionReasonCode {
        GroupSelectionReasonCode(rawValue: reasonCode) ?? .noHealthyCandidate
    }

    private enum CodingKeys: String, CodingKey {
        case groupID
        case policy
        case selectedServerID
        case reasonCode
    }
}

public struct ServerSelectionEvaluator: Sendable {
    public static let defaultStaleAfter: TimeInterval = 300

    public let staleAfter: TimeInterval

    public init(staleAfter: TimeInterval = ServerSelectionEvaluator.defaultStaleAfter) {
        self.staleAfter = staleAfter
    }

    public func select(_ request: ServerSelectionRequest) -> GroupSelectionDecision {
        let group = request.group
        let policy = group.selectionPolicy
        let staleAfter = request.staleAfter ?? staleAfter

        guard !group.members.isEmpty else {
            return decision(group: group, policy: policy, serverID: nil, reason: .emptyGroup)
        }

        switch policy {
        case .manual:
            guard let requestedServerID = request.requestedServerID else {
                return decision(group: group, policy: policy, serverID: nil, reason: .manualSelectionRequired)
            }
            guard group.contains(requestedServerID) else {
                return decision(
                    group: group,
                    policy: policy,
                    serverID: nil,
                    reason: .requestedServerNotMember
                )
            }
            return decision(group: group, policy: policy, serverID: requestedServerID, reason: .selected)

        case .lowestLatency:
            return selectLowestLatency(
                group: group,
                policy: policy,
                snapshot: request.healthSnapshot,
                now: request.now,
                staleAfter: staleAfter
            )

        case .failover:
            return selectFailover(
                group: group,
                policy: policy,
                snapshot: request.healthSnapshot,
                now: request.now,
                staleAfter: staleAfter
            )
        }
    }

    public func select(
        _ group: ServerGroup,
        requestedServerID: UUID? = nil,
        healthSnapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) -> GroupSelectionDecision {
        select(
            ServerSelectionRequest(
                group: group,
                requestedServerID: requestedServerID,
                healthSnapshot: healthSnapshot,
                now: now,
                staleAfter: staleAfter
            )
        )
    }

    public func select(
        _ group: ServerGroup,
        healthSnapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) -> GroupSelectionDecision {
        select(
            group,
            requestedServerID: nil,
            healthSnapshot: healthSnapshot,
            now: now,
            staleAfter: staleAfter
        )
    }

    public func select(
        _ group: ServerGroup,
        snapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) -> GroupSelectionDecision {
        select(
            group,
            requestedServerID: nil,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: staleAfter
        )
    }

    public func select(
        _ group: ServerGroup,
        requestedServerID: UUID? = nil,
        snapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) -> GroupSelectionDecision {
        select(
            group,
            requestedServerID: requestedServerID,
            healthSnapshot: snapshot,
            now: now,
            staleAfter: staleAfter
        )
    }

    public func select(
        group: ServerGroup,
        requestedServerID: UUID? = nil,
        healthSnapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) -> GroupSelectionDecision {
        select(
            group,
            requestedServerID: requestedServerID,
            healthSnapshot: healthSnapshot,
            now: now,
            staleAfter: staleAfter
        )
    }

    public func select(
        group: ServerGroup,
        requestedServerID: UUID? = nil,
        health: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) -> GroupSelectionDecision {
        select(
            group,
            requestedServerID: requestedServerID,
            healthSnapshot: health,
            now: now,
            staleAfter: staleAfter
        )
    }

    public func select(
        group: ServerGroup,
        health: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval? = nil
    ) -> GroupSelectionDecision {
        select(
            group,
            requestedServerID: nil,
            healthSnapshot: health,
            now: now,
            staleAfter: staleAfter
        )
    }

    private func selectLowestLatency(
        group: ServerGroup,
        policy: SelectionPolicy,
        snapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval
    ) -> GroupSelectionDecision {
        var bestServerID: UUID?
        var bestLatency: TimeInterval?
        var sawInvalidLatency = false
        var sawStaleSample = false

        for memberID in group.members {
            guard let sample = snapshot.sample(for: memberID), sample.isHealthy else { continue }
            guard isFresh(sample: sample, now: now, staleAfter: staleAfter) else {
                sawStaleSample = true
                continue
            }
            guard let latency = sample.latency, latency.isFinite, latency >= 0 else {
                sawInvalidLatency = true
                continue
            }
            if bestLatency == nil || latency < bestLatency! {
                bestLatency = latency
                bestServerID = memberID
            }
        }

        if let bestServerID {
            return decision(group: group, policy: policy, serverID: bestServerID, reason: .selected)
        }
        if sawInvalidLatency && !sawStaleSample {
            return decision(group: group, policy: policy, serverID: nil, reason: .noValidLatency)
        }
        if sawStaleSample && !sawInvalidLatency {
            return decision(group: group, policy: policy, serverID: nil, reason: .staleHealthSample)
        }
        return decision(group: group, policy: policy, serverID: nil, reason: .noHealthyCandidate)
    }

    private func selectFailover(
        group: ServerGroup,
        policy: SelectionPolicy,
        snapshot: HealthSnapshot,
        now: Date,
        staleAfter: TimeInterval
    ) -> GroupSelectionDecision {
        var sawStaleSample = false
        var sawUnavailableSample = false

        for memberID in group.members {
            guard let sample = snapshot.sample(for: memberID) else {
                sawUnavailableSample = true
                continue
            }
            guard sample.isHealthy else {
                sawUnavailableSample = true
                continue
            }
            guard isFresh(sample: sample, now: now, staleAfter: staleAfter) else {
                sawStaleSample = true
                continue
            }
            return decision(group: group, policy: policy, serverID: memberID, reason: .selected)
        }

        let reason: GroupSelectionReasonCode = sawStaleSample && !sawUnavailableSample
            ? .staleHealthSample
            : .noHealthyCandidate
        return decision(group: group, policy: policy, serverID: nil, reason: reason)
    }

    private func isFresh(sample: HealthSample, now: Date, staleAfter: TimeInterval) -> Bool {
        guard staleAfter.isFinite, staleAfter >= 0 else { return false }
        let age = now.timeIntervalSince(sample.observedAt)
        return age >= 0 && age <= staleAfter
    }

    private func decision(
        group: ServerGroup,
        policy: SelectionPolicy,
        serverID: UUID?,
        reason: GroupSelectionReasonCode
    ) -> GroupSelectionDecision {
        GroupSelectionDecision(
            groupID: group.id,
            policy: policy,
            selectedServerID: serverID,
            reasonCode: reason.rawValue
        )
    }
}

public typealias ServerSelectionInput = ServerSelectionRequest
public typealias GroupSelectionResult = GroupSelectionDecision
public typealias HealthObservation = HealthSample
public typealias GroupSelectionReason = GroupSelectionReasonCode
