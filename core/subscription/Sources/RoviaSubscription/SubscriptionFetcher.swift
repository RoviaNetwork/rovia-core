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
    case emptyBody
    case tooLarge
    case networkError
}

/// Minimal session surface the fetcher needs. `URLSession` conforms, tests
/// inject a stub — no `URLProtocol` subclassing, no real sockets in tests.
public protocol SubscriptionHTTPSession: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

extension URLSession: SubscriptionHTTPSession {
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await data(for: request, delegate: nil)
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
    private let session: any SubscriptionHTTPSession
    public let policy: SubscriptionFetchPolicy

    public init(
        session: any SubscriptionHTTPSession = URLSession.shared,
        policy: SubscriptionFetchPolicy = SubscriptionFetchPolicy()
    ) {
        self.session = session
        self.policy = policy
    }

    /// Downloads a subscription URL: raw bytes plus optional provider
    /// metadata. Decoding stays in `SubscriptionDocumentDecoder`. Errors
    /// never carry the URL: tokens live in query strings, and must not end
    /// up in logs or error surfaces.
    public func fetch(_ url: URL) async throws -> SubscriptionFetchResult {
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
        var request = URLRequest(
            url: url,
            cachePolicy: .reloadIgnoringLocalCacheData,
            timeoutInterval: policy.timeout
        )
        request.httpMethod = "GET"
        request.setValue("text/plain, */*;q=0.8", forHTTPHeaderField: "Accept")
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch is CancellationError {
            throw SubscriptionFetchError.cancelled
        } catch let error as URLError where error.code == .cancelled {
            throw SubscriptionFetchError.cancelled
        } catch let error as URLError where error.code == .timedOut {
            throw SubscriptionFetchError.timedOut
        } catch {
            throw SubscriptionFetchError.networkError
        }
        guard let http = response as? HTTPURLResponse else {
            throw SubscriptionFetchError.networkError
        }
        guard (200..<300).contains(http.statusCode) else {
            throw SubscriptionFetchError.httpStatus(http.statusCode)
        }
        guard !data.isEmpty else {
            throw SubscriptionFetchError.emptyBody
        }
        guard data.count <= policy.maximumBytes else {
            throw SubscriptionFetchError.tooLarge
        }
        let rawUserInfo = http.value(forHTTPHeaderField: "subscription-userinfo")
        let userInfo = rawUserInfo.map(SubscriptionUserInfo.parse(header:)).flatMap { $0.isEmpty ? nil : $0 }
        return SubscriptionFetchResult(data: data, userInfo: userInfo)
    }
}
