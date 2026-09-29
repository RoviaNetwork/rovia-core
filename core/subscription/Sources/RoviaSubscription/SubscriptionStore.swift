import Foundation
import RoviaConfig

public enum SubscriptionStoreError: Error, Equatable, Sendable {
    case unknownSubscription
    case persistenceFailed
}

/// One persisted subscription: redacted metadata plus the last working
/// server list. Secrets are never stored here — the import credential sink
/// writes them to the Keychain (`KeychainSecretStore`), keyed per server.
public struct StoredSubscription: Equatable, Sendable, Identifiable {
    /// Store format version. v1 hashed raw link lines for server IDs;
    /// v2 hashes canonical lines and namespaces summary IDs per
    /// subscription. Legacy files decode as v1; the app migrates them on
    /// the next refresh (one ID rotation, then stable).
    public static let currentSchemaVersion = 2

    public let id: UUID
    public var name: String
    public var source: SubscriptionSource
    public var servers: [Server]
    public var acceptedCount: Int
    public var rejectedCount: Int
    public var updatedAt: Date
    /// Last provider-reported traffic/expiry, if the provider sends
    /// `subscription-userinfo`. Absent for pasted imports and old files.
    public var userInfo: SubscriptionUserInfo?
    /// Explicit opt-in to plain-HTTP fetch for this subscription only.
    /// Decoded with a default so files written before this field exist
    /// keep loading.
    public var allowInsecure: Bool
    public var schemaVersion: Int

    public init(
        id: UUID = UUID(),
        name: String,
        source: SubscriptionSource,
        servers: [Server] = [],
        acceptedCount: Int = 0,
        rejectedCount: Int = 0,
        updatedAt: Date = Date(),
        allowInsecure: Bool = false,
        userInfo: SubscriptionUserInfo? = nil,
        schemaVersion: Int = StoredSubscription.currentSchemaVersion
    ) {
        self.id = id
        self.name = name
        self.source = source
        self.servers = servers
        self.acceptedCount = acceptedCount
        self.rejectedCount = rejectedCount
        self.updatedAt = updatedAt
        self.allowInsecure = allowInsecure
        self.userInfo = userInfo
        self.schemaVersion = schemaVersion
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case source
        case servers
        case acceptedCount
        case rejectedCount
        case updatedAt
        case allowInsecure
        case userInfo
        case schemaVersion
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        source = try container.decode(SubscriptionSource.self, forKey: .source)
        servers = try container.decode([Server].self, forKey: .servers)
        acceptedCount = try container.decode(Int.self, forKey: .acceptedCount)
        rejectedCount = try container.decode(Int.self, forKey: .rejectedCount)
        updatedAt = try container.decode(Date.self, forKey: .updatedAt)
        allowInsecure = try container.decodeIfPresent(Bool.self, forKey: .allowInsecure) ?? false
        schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
        userInfo = try container.decodeIfPresent(SubscriptionUserInfo.self, forKey: .userInfo)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(source, forKey: .source)
        try container.encode(servers, forKey: .servers)
        try container.encode(acceptedCount, forKey: .acceptedCount)
        try container.encode(rejectedCount, forKey: .rejectedCount)
        try container.encode(updatedAt, forKey: .updatedAt)
        try container.encode(allowInsecure, forKey: .allowInsecure)
        try container.encodeIfPresent(userInfo, forKey: .userInfo)
        try container.encode(schemaVersion, forKey: .schemaVersion)
    }
}

extension StoredSubscription: Codable {}

/// File-backed subscription list. Refresh is atomic by construction: a
/// failed download or an empty import throws before `replaceServers` runs,
/// so the last working server list (and the selected server, via stable
/// importer IDs) always survives.
public actor SubscriptionStore {
    private let fileURL: URL
    private var records: [StoredSubscription] = []
    private var loaded = false

    public init(directory: URL, fileName: String = "subscriptions.json") {
        self.fileURL = directory.appendingPathComponent(fileName)
    }

    public func load() throws {
        guard !loaded else { return }
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            records = []
            loaded = true
            return
        }
        // `loaded` flips only on success: a corrupt file throws and the next
        // `load` really reads again instead of returning nothing.
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch {
            throw SubscriptionStoreError.persistenceFailed
        }
        do {
            records = try JSONDecoder().decode([StoredSubscription].self, from: data)
        } catch {
            throw SubscriptionStoreError.persistenceFailed
        }
        loaded = true
    }

    public func subscriptions() -> [StoredSubscription] {
        records
    }

    public func upsert(_ record: StoredSubscription) throws {
        var next = records
        if let index = next.firstIndex(where: { $0.id == record.id }) {
            next[index] = record
        } else {
            next.append(record)
        }
        try persist(next)
        records = next
    }

    public func rename(id: UUID, name: String) throws {
        guard let index = records.firstIndex(where: { $0.id == id }) else {
            throw SubscriptionStoreError.unknownSubscription
        }
        var next = records
        next[index].name = name
        try persist(next)
        records = next
    }

    public func remove(id: UUID) throws {
        guard let index = records.firstIndex(where: { $0.id == id }) else {
            throw SubscriptionStoreError.unknownSubscription
        }
        var next = records
        next.remove(at: index)
        try persist(next)
        records = next
    }

    /// Atomic refresh update. Call only after a successful import; network
    /// and decode failures never reach this method, which is what keeps the
    /// last working version on disk. `userInfo` overwrites unconditionally:
    /// a refresh carries the latest provider state, including its absence.
    public func replaceServers(
        id: UUID,
        servers: [Server],
        acceptedCount: Int,
        rejectedCount: Int,
        updatedAt: Date = Date(),
        userInfo: SubscriptionUserInfo? = nil
    ) throws {
        guard let index = records.firstIndex(where: { $0.id == id }) else {
            throw SubscriptionStoreError.unknownSubscription
        }
        var next = records
        next[index].servers = servers
        next[index].acceptedCount = acceptedCount
        next[index].rejectedCount = rejectedCount
        next[index].updatedAt = updatedAt
        next[index].userInfo = userInfo
        try persist(next)
        records = next
    }

    private func persist(_ records: [StoredSubscription]) throws {
        do {
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let data = try JSONEncoder().encode(records)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            throw SubscriptionStoreError.persistenceFailed
        }
    }
}
