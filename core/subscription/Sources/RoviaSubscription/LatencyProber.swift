import Foundation
import Network

/// TCP-connect latency. A successful handshake proves the endpoint accepts
/// connections; it says nothing about proxy protocol health — that needs the
/// engine. Timeouts and refusals both report `nil`: the UI shows
/// "Not measured", never a fake number.
private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func run(_ body: () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        guard !done else { return }
        done = true
        body()
    }
}

public enum LatencyProber {
    public static func probe(host: String, port: Int, timeout: TimeInterval = 3) async -> Int? {
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? 443,
            using: .tcp
        )
        let started = ContinuousClock().now
        return await withCheckedContinuation { continuation in
            let once = ResumeOnce()
            let finish: @Sendable (Int?) -> Void = { milliseconds in
                once.run {
                    connection.cancel()
                    continuation.resume(returning: milliseconds)
                }
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let elapsed = ContinuousClock().now - started
                    let ms = Int(elapsed.components.seconds * 1_000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
                    finish(ms)
                case .failed, .cancelled:
                    finish(nil)
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .utility))
            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                finish(nil)
            }
        }
    }

    /// Probes every endpoint with at most `maxConcurrent` handshakes in
    /// flight. Unbounded probing against thousands of servers would open
    /// thousands of sockets and drain the battery for numbers nobody reads —
    /// the caller caps the input list as well.
    public static func probeAll(
        _ endpoints: [(host: String, port: Int)],
        maxConcurrent: Int = 6,
        timeout: TimeInterval = 3
    ) async -> [Int?] {
        var results = Array<Int?>(repeating: nil, count: endpoints.count)
        let stride = max(1, maxConcurrent)
        var offset = 0
        while offset < endpoints.count {
            let end = min(offset + stride, endpoints.count)
            await withTaskGroup(of: (Int, Int?).self) { group in
                for index in offset..<end {
                    group.addTask {
                        let endpoint = endpoints[index]
                        return (index, await probe(host: endpoint.host, port: endpoint.port, timeout: timeout))
                    }
                }
                for await (index, milliseconds) in group {
                    results[index] = milliseconds
                }
            }
            offset = end
        }
        return results
    }
}
