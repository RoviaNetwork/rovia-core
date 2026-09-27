import Foundation
import RoviaConfig

public struct EngineDescriptor: Codable, Sendable, Equatable {
    public let id: String
    public let name: String
    public let version: String

    public init(id: String, name: String, version: String) {
        self.id = id
        self.name = name
        self.version = version
    }
}

public struct EngineCapabilities: Codable, Sendable, Equatable {
    public let supportsTunnel: Bool
    public let supportsHealthProbe: Bool
    public let supportsRouting: Bool
    public let supportedProtocols: [ProxyProtocol]

    public init(
        supportsTunnel: Bool,
        supportsHealthProbe: Bool,
        supportsRouting: Bool,
        supportedProtocols: [ProxyProtocol]
    ) {
        self.supportsTunnel = supportsTunnel
        self.supportsHealthProbe = supportsHealthProbe
        self.supportsRouting = supportsRouting
        self.supportedProtocols = supportedProtocols
    }
}

public struct CanonicalTunnelConfiguration: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let appConfig: AppConfig

    public init(schemaVersion: Int, appConfig: AppConfig) {
        self.schemaVersion = schemaVersion
        self.appConfig = appConfig
    }
}

public struct ValidationReport: Codable, Sendable, Equatable {
    public let valid: Bool
    public let warnings: [String]

    public init(valid: Bool, warnings: [String]) {
        self.valid = valid
        self.warnings = warnings
    }
}

public struct PreparedEngineConfiguration: Codable, Sendable, Equatable {
    public let engineID: String
    public let opaquePayload: Data

    public init(engineID: String, opaquePayload: Data) {
        self.engineID = engineID
        self.opaquePayload = opaquePayload
    }
}

public struct EnginePacket: Codable, Sendable, Equatable {
    public let data: Data
    public let protocolNumber: Int32

    public init(data: Data, protocolNumber: Int32) {
        self.data = data
        self.protocolNumber = protocolNumber
    }
}

public protocol PacketBridge: Sendable {
    func read() async throws -> [EnginePacket]
    func write(_ packets: [EnginePacket]) async throws
}

public struct TunnelRuntimeContext: Sendable {
    public let sessionID: UUID
    public let platform: String
    public let preparedConfiguration: PreparedEngineConfiguration
    public let packetBridge: any PacketBridge
    public let metadata: [String: String]

    public init(
        sessionID: UUID,
        platform: String,
        preparedConfiguration: PreparedEngineConfiguration,
        packetBridge: any PacketBridge,
        metadata: [String: String] = [:]
    ) {
        self.sessionID = sessionID
        self.platform = platform
        self.preparedConfiguration = preparedConfiguration
        self.packetBridge = packetBridge
        self.metadata = metadata
    }
}

public enum EngineStatus: Codable, Sendable, Equatable {
    case unavailable
    case idle
    case preparing
    case running
    case stopping
    case failed(String)

    private enum CodingKeys: String, CodingKey {
        case type
        case message
    }

    private enum Kind: String, Codable {
        case unavailable
        case idle
        case preparing
        case running
        case stopping
        case failed
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .type) {
        case .unavailable: self = .unavailable
        case .idle: self = .idle
        case .preparing: self = .preparing
        case .running: self = .running
        case .stopping: self = .stopping
        case .failed: self = .failed(try container.decode(String.self, forKey: .message))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .unavailable: try container.encode(Kind.unavailable, forKey: .type)
        case .idle: try container.encode(Kind.idle, forKey: .type)
        case .preparing: try container.encode(Kind.preparing, forKey: .type)
        case .running: try container.encode(Kind.running, forKey: .type)
        case .stopping: try container.encode(Kind.stopping, forKey: .type)
        case let .failed(message):
            try container.encode(Kind.failed, forKey: .type)
            try container.encode(message, forKey: .message)
        }
    }
}

public struct HealthProbeRequest: Codable, Sendable, Equatable {
    public let serverID: UUID
    public let timeout: TimeInterval
    public let targetURL: String?

    public init(serverID: UUID, timeout: TimeInterval, targetURL: String? = nil) {
        self.serverID = serverID
        self.timeout = timeout
        self.targetURL = targetURL
    }
}

public enum HealthFailure: Codable, Sendable, Equatable {
    case timeout
    case connectionRefused
    case authentication
    case protocolFailure
    case unknown

    private enum CodingKeys: String, CodingKey {
        case type
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .type) {
        case "timeout": self = .timeout
        case "connectionRefused": self = .connectionRefused
        case "authentication": self = .authentication
        case "protocol": self = .protocolFailure
        case "unknown": self = .unknown
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "Unknown health failure")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .timeout: try container.encode("timeout", forKey: .type)
        case .connectionRefused: try container.encode("connectionRefused", forKey: .type)
        case .authentication: try container.encode("authentication", forKey: .type)
        case .protocolFailure: try container.encode("protocol", forKey: .type)
        case .unknown: try container.encode("unknown", forKey: .type)
        }
    }
}

public struct HealthProbeResult: Codable, Sendable, Equatable {
    public let serverID: UUID
    public let succeeded: Bool
    public let latencyMilliseconds: Double?
    public let failure: HealthFailure?

    public init(serverID: UUID, succeeded: Bool, latencyMilliseconds: Double?, failure: HealthFailure? = nil) {
        self.serverID = serverID
        self.succeeded = succeeded
        self.latencyMilliseconds = latencyMilliseconds
        self.failure = failure
    }
}

public enum EngineError: Error, Equatable, Sendable {
    case notIncludedInBuild(String)
    case unsupportedCapability(String)
    case invalidConfiguration(String)
    case runtimeFailure(String)
}

public protocol TunnelEngine: Sendable {
    var descriptor: EngineDescriptor { get }

    func capabilities() async -> EngineCapabilities
    func validate(_ configuration: CanonicalTunnelConfiguration) async throws -> ValidationReport
    func prepare(_ configuration: CanonicalTunnelConfiguration) async throws -> PreparedEngineConfiguration
    func start(_ context: TunnelRuntimeContext) async throws
    func stop() async
    func status() async -> EngineStatus
    func probe(_ request: HealthProbeRequest) async throws -> HealthProbeResult
}

public protocol EngineConfigCompiler {
    associatedtype Output

    func compile(_ configuration: CanonicalTunnelConfiguration) throws -> Output
}
