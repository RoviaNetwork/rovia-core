import Foundation

public struct SubscriptionFetchPolicy: Equatable, Sendable {
    /// HTTPS is always allowed. HTTP needs an explicit opt-in per
    /// subscription — TLS verification is never disabled globally.
    public var allowInsecureHTTP: Bool
    public var timeout: TimeInterval
    public var maximumBytes: Int

    public init(
        allowInsecureHTTP: Bool = false,
        timeout: TimeInterval = 30,
        maximumBytes: Int = SubscriptionLimits.maximumBytes
    ) {
        self.allowInsecureHTTP = allowInsecureHTTP
        self.timeout = timeout
        self.maximumBytes = maximumBytes
    }
}

/// Traffic and expiry metadata a provider may send in the
/// `subscription-userinfo` response header
/// (`upload=…; download=…; total=…; expire=…`). Everything is optional:
/// the UI shows a field only when the provider sent it.
public struct SubscriptionUserInfo: Codable, Equatable, Sendable {
    public var uploadBytes: Int64?
    public var downloadBytes: Int64?
    public var totalBytes: Int64?
    public var expireDate: Date?

    public init(uploadBytes: Int64? = nil, downloadBytes: Int64? = nil, totalBytes: Int64? = nil, expireDate: Date? = nil) {
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
        self.totalBytes = totalBytes
        self.expireDate = expireDate
    }

    public static func parse(header value: String) -> SubscriptionUserInfo {
        var info = SubscriptionUserInfo()
        for part in value.split(separator: ";") {
            let pair = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard pair.count == 2 else { continue }
            switch pair[0].lowercased() {
            case "upload": info.uploadBytes = Int64(pair[1])
            case "download": info.downloadBytes = Int64(pair[1])
            case "total": info.totalBytes = Int64(pair[1])
            case "expire":
                if let seconds = TimeInterval(pair[1]), seconds > 0 {
                    info.expireDate = Date(timeIntervalSince1970: seconds)
                }
            default: continue
            }
        }
        return info
    }

    public var isEmpty: Bool {
        uploadBytes == nil && downloadBytes == nil && totalBytes == nil && expireDate == nil
    }
}

public enum SubscriptionFetchError: Error, Equatable, Sendable {
    case invalidURL
    case insecureSchemeBlocked
    case cancelled
    case timedOut
    case httpStatus(Int)
    case redirectBlocked
    case emptyBody
    case tooLarge
    case networkError
}

/// Minimal session surface the fetcher needs. Tests inject a stub — no
/// `URLProtocol` subclassing. The stub path loads whole bodies, so it only
/// suits unit tests with tiny payloads; the production path below streams
/// with a byte cap, and the local-server integration tests cover it.
public protocol SubscriptionHTTPSession: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

extension URLSession: SubscriptionHTTPSession {
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await data(for: request, delegate: nil)
    }
}

/// Enforces the redirect policy hop by hop: http/https with a host only, at
/// most five hops, and no HTTPS→HTTP downgrade without the per-subscription
/// insecure opt-in. Anything else is refused, and the refused hop surfaces
/// as the 3xx response — which the fetcher reports as `redirectBlocked`,
/// never as a successful body. TLS evaluation itself is never touched.
final class SubscriptionRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    static let maximumRedirects = 5

    private let policy: SubscriptionFetchPolicy
    private let lock = NSLock()
    private var hops: [Int: Int] = [:]

    init(policy: SubscriptionFetchPolicy) {
        self.policy = policy
    }

    /// Pure redirect decision, unit-tested separately: the delegate only
    /// counts hops and forwards here. `fromScheme` is the responding URL's
    /// scheme (`response.url`), because that is the hop being left.
    static func allowsRedirect(
        fromScheme: String?,
        to url: URL,
        hops: Int,
        policy: SubscriptionFetchPolicy
    ) -> Bool {
        guard let scheme = url.scheme?.lowercased(),
              (scheme == "https" || scheme == "http"),
              let host = url.host, !host.isEmpty
        else {
            return false
        }
        if fromScheme?.lowercased() == "https" && scheme == "http" && !policy.allowInsecureHTTP {
            return false
        }
        return hops < maximumRedirects
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        lock.lock()
        let completed = hops[task.taskIdentifier] ?? 0
        lock.unlock()
        guard let target = request.url,
              Self.allowsRedirect(
                  fromScheme: response.url?.scheme,
                  to: target,
                  hops: completed,
                  policy: policy
              )
        else {
            completionHandler(nil)
            return
        }
        lock.lock()
        hops[task.taskIdentifier] = completed + 1
        lock.unlock()
        completionHandler(request)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        hops.removeValue(forKey: task.taskIdentifier)
        lock.unlock()
    }
}

/// Raw download plus optional provider metadata. The URL itself never
/// appears here or in any error: tokens live in query strings.
public struct SubscriptionFetchResult: Equatable, Sendable {
    public let data: Data
    public let userInfo: SubscriptionUserInfo?

    public init(data: Data, userInfo: SubscriptionUserInfo? = nil) {
        self.data = data
        self.userInfo = userInfo
    }
}

public struct SubscriptionFetcher: Sendable {
    private enum Transport: Sendable {
        case injected(any SubscriptionHTTPSession)
        /// Streaming production path. No live session is stored: every fetch
        /// builds its own ephemeral session with a fresh redirect delegate
        /// and invalidates it before returning, so finished downloads never
        /// leave sessions or tasks behind. A stored session would also pin
        /// one policy's redirect rules while the coordinator varies
        /// `allowInsecureHTTP` per subscription.
        case managed
    }

    private let transport: Transport
    public let policy: SubscriptionFetchPolicy

    /// Injectable transport for unit tests (whole-body stubs).
    public init(
        session: any SubscriptionHTTPSession = URLSession.shared,
        policy: SubscriptionFetchPolicy = SubscriptionFetchPolicy()
    ) {
        self.transport = .injected(session)
        self.policy = policy
    }

    /// Production transport: streaming bodies with a byte cap, hop-by-hop
    /// redirect control, per-call policy. Integration-tested against a local
    /// HTTP server (redirects, slow streams, oversized bodies, cancellation,
    /// HTTP errors).
    public static func production(policy: SubscriptionFetchPolicy = SubscriptionFetchPolicy()) -> SubscriptionFetcher {
        SubscriptionFetcher(transport: .managed, policy: policy)
    }

    private init(transport: Transport, policy: SubscriptionFetchPolicy) {
        self.transport = transport
        self.policy = policy
    }

    /// Downloads a subscription URL: raw bytes plus optional provider
    /// metadata. Decoding stays in `SubscriptionDocumentDecoder`. Errors
    /// never carry the URL: tokens live in query strings, and must not end
    /// up in logs or error surfaces.
    ///
    /// - Parameter policy: overrides the stored policy for this call. The
    ///   coordinator passes a per-subscription policy (`allowInsecureHTTP`
    ///   varies per subscription); the default keeps the stored one, so
    ///   existing call sites are unaffected.
    public func fetch(_ url: URL, policy override: SubscriptionFetchPolicy? = nil) async throws -> SubscriptionFetchResult {
        let effective = override ?? policy
        try Self.validateScheme(url, policy: effective)
        let request = Self.baseRequest(url: url, policy: effective)
        switch transport {
        case let .injected(session):
            let (data, response): (Data, URLResponse)
            do {
                (data, response) = try await session.data(for: request)
            } catch {
                throw Self.mapSessionError(error)
            }
            return try Self.validatedResult(data: data, response: response, maximumBytes: effective.maximumBytes)
        case .managed:
            return try await Self.streamedResult(request: request, policy: effective)
        }
    }

    private static func validateScheme(_ url: URL, policy: SubscriptionFetchPolicy) throws {
        guard let scheme = url.scheme?.lowercased(), let host = url.host, !host.isEmpty else {
            throw SubscriptionFetchError.invalidURL
        }
        switch scheme {
        case "https":
            break
        case "http":
            guard policy.allowInsecureHTTP else {
                throw SubscriptionFetchError.insecureSchemeBlocked
            }
        default:
            throw SubscriptionFetchError.invalidURL
        }
    }

    private static func baseRequest(url: URL, policy: SubscriptionFetchPolicy) -> URLRequest {
        var request = URLRequest(
            url: url,
            cachePolicy: .reloadIgnoringLocalCacheData,
            timeoutInterval: policy.timeout
        )
        request.httpMethod = "GET"
        request.setValue("text/plain, */*;q=0.8", forHTTPHeaderField: "Accept")
        return request
    }

    /// Streams the body, counting actual bytes — `Content-Length` is never
    /// trusted as the only guard, and a missing length changes nothing.
    /// Cancellation aborts the read; the overall deadline guards stalls the
    /// request timeout does not cover. The session is built per call and
    /// invalidated before returning: no live session outlives a finished
    /// download.
    private static func streamedResult(request: URLRequest, policy: SubscriptionFetchPolicy) async throws -> SubscriptionFetchResult {
        // Cancellation of the caller must surface as `.cancelled`, not as a
        // raw `CancellationError` escaping from the deadline group below.
        let delegate = SubscriptionRedirectDelegate(policy: policy)
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        do {
            return try await withDeadline(seconds: policy.timeout) {
            let (bytes, response): (URLSession.AsyncBytes, URLResponse)
            do {
                (bytes, response) = try await session.bytes(for: request)
            } catch {
                throw Self.mapSessionError(error)
            }
            guard let http = response as? HTTPURLResponse else {
                throw SubscriptionFetchError.networkError
            }
            if (300..<400).contains(http.statusCode) {
                throw SubscriptionFetchError.redirectBlocked
            }
            guard (200..<300).contains(http.statusCode) else {
                throw SubscriptionFetchError.httpStatus(http.statusCode)
            }
            var data = Data()
            data.reserveCapacity(min(65536, policy.maximumBytes))
            do {
                for try await byte in bytes {
                    try Task.checkCancellation()
                    data.append(byte)
                    guard data.count <= policy.maximumBytes else {
                        throw SubscriptionFetchError.tooLarge
                    }
                }
            } catch is CancellationError {
                throw SubscriptionFetchError.cancelled
            } catch let error as SubscriptionFetchError {
                throw error
            } catch let error as URLError where error.code == .cancelled {
                throw SubscriptionFetchError.cancelled
            } catch {
                throw SubscriptionFetchError.networkError
            }
            return try Self.validatedResult(data: data, response: response, maximumBytes: policy.maximumBytes)
            }
        } catch is CancellationError {
            throw SubscriptionFetchError.cancelled
        }
    }

    private static func validatedResult(data: Data, response: URLResponse, maximumBytes: Int) throws -> SubscriptionFetchResult {
        guard let http = response as? HTTPURLResponse else {
            throw SubscriptionFetchError.networkError
        }
        if (300..<400).contains(http.statusCode) {
            throw SubscriptionFetchError.redirectBlocked
        }
        guard (200..<300).contains(http.statusCode) else {
            throw SubscriptionFetchError.httpStatus(http.statusCode)
        }
        guard !data.isEmpty else {
            throw SubscriptionFetchError.emptyBody
        }
        guard data.count <= maximumBytes else {
            throw SubscriptionFetchError.tooLarge
        }
        let rawUserInfo = http.value(forHTTPHeaderField: "subscription-userinfo")
        let userInfo = rawUserInfo.map(SubscriptionUserInfo.parse(header:)).flatMap { $0.isEmpty ? nil : $0 }
        return SubscriptionFetchResult(data: data, userInfo: userInfo)
    }

    private static func mapSessionError(_ error: Error) -> SubscriptionFetchError {
        if error is CancellationError {
            return .cancelled
        }
        if let urlError = error as? URLError {
            switch urlError.code {
            case .cancelled: return .cancelled
            case .timedOut: return .timedOut
            default: return .networkError
            }
        }
        return .networkError
    }

    private static func withDeadline<T: Sendable>(
        seconds: TimeInterval,
        operation: @Sendable @escaping () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(max(1, seconds) * 1_000_000_000))
                throw SubscriptionFetchError.timedOut
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else {
                throw SubscriptionFetchError.networkError
            }
            group.cancelAll()
            return result
        }
    }
}
