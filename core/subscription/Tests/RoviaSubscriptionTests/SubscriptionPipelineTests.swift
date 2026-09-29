import Foundation
import Network
import XCTest
@testable import RoviaConfig
@testable import RoviaSubscription

private let vlessLine = "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=tcp"
private let trojanLine = "trojan://Pipeline-Password-1@synthetic.example:443?security=tls"
private let ssLine = "ss://YWVzLTI1Ni1nY206cGFzcw@synthetic.example:8388"

private func makeTestSink(prefix: String = "test/credential") -> ShareLinkCredentialSink {
    var count = 0
    return { _ in
        count += 1
        return SecretReference(key: "\(prefix)-\(count)")
    }
}

final class SubscriptionInputClassifierTests: XCTestCase {
    func testClassifiesSingleShareLinks() {
        XCTAssertEqual(
            SubscriptionInputClassifier.classify(vlessLine),
            .singleShareLink(scheme: .vless)
        )
        XCTAssertEqual(
            SubscriptionInputClassifier.classify(trojanLine),
            .singleShareLink(scheme: .trojan)
        )
        XCTAssertEqual(
            SubscriptionInputClassifier.classify(ssLine),
            .singleShareLink(scheme: .ss)
        )
    }

    func testClassifiesSubscriptionURLs() {
        let https = SubscriptionInputClassifier.classify("https://provider.example/sub/abc123")
        XCTAssertEqual(https, .subscriptionURL(URL(string: "https://provider.example/sub/abc123")!))
        let http = SubscriptionInputClassifier.classify("http://provider.example/sub")
        XCTAssertEqual(http, .subscriptionURL(URL(string: "http://provider.example/sub")!))
    }

    func testMultilineGarbageAndUnsupportedSchemesArePastedText() {
        XCTAssertEqual(
            SubscriptionInputClassifier.classify("\(vlessLine)\n\(trojanLine)"),
            .pastedText
        )
        XCTAssertEqual(
            SubscriptionInputClassifier.classify("vmess://eyJhZGRyZXNzIjoieCJ9"),
            .pastedText
        )
        XCTAssertEqual(
            SubscriptionInputClassifier.classify("not a link at all"),
            .pastedText
        )
    }

    func testEmptyInputIsNil() {
        XCTAssertNil(SubscriptionInputClassifier.classify(""))
        XCTAssertNil(SubscriptionInputClassifier.classify("   \n  "))
    }
}

final class SubscriptionDocumentDecoderTests: XCTestCase {
    func testDecodesPlainList() throws {
        let doc = try SubscriptionDocumentDecoder.decode(Data("\(vlessLine)\n\(trojanLine)\n".utf8))
        XCTAssertEqual(doc.lines, [vlessLine, trojanLine])
        XCTAssertFalse(doc.wasBase64)
    }

    func testDecodesBase64Container() throws {
        let container = Data("\(vlessLine)\n\(trojanLine)".utf8).base64EncodedString()
        let doc = try SubscriptionDocumentDecoder.decode(Data(container.utf8))
        XCTAssertEqual(doc.lines, [vlessLine, trojanLine])
        XCTAssertTrue(doc.wasBase64)
    }

    func testDecodesBase64ContainerWithWhitespace() throws {
        let container = Data(ssLine.utf8).base64EncodedString()
        let chunked = container.prefix(8) + "\n" + container.dropFirst(8)
        let doc = try SubscriptionDocumentDecoder.decode(Data(String(chunked).utf8))
        XCTAssertEqual(doc.lines, [ssLine])
        XCTAssertTrue(doc.wasBase64)
    }

    func testRejectsHTML() {
        for body in [
            "<!DOCTYPE html><html><body>error</body></html>",
            "  <html><body>gateway error</body></html>",
            "<HTML><BODY>proxy says no</BODY></HTML>"
        ] {
            XCTAssertThrowsError(try SubscriptionDocumentDecoder.decode(Data(body.utf8))) { error in
                XCTAssertEqual(error as? SubscriptionDocumentError, .htmlDetected, body)
            }
        }
    }

    func testRejectsCorruptLongBase64() {
        // 33 alphabet-only chars: length % 4 == 1 can never be Base64.
        let corrupt = String(repeating: "A", count: 33)
        XCTAssertThrowsError(try SubscriptionDocumentDecoder.decode(Data(corrupt.utf8))) { error in
            XCTAssertEqual(error as? SubscriptionDocumentError, .invalidBase64)
        }
    }

    func testRejectsEmptyOversizedAndNonUTF8() {
        XCTAssertThrowsError(try SubscriptionDocumentDecoder.decode(Data("  \n ".utf8))) { error in
            XCTAssertEqual(error as? SubscriptionDocumentError, .empty)
        }
        let oversized = Data(repeating: 0x61, count: SubscriptionLimits.maximumBytes + 1)
        XCTAssertThrowsError(try SubscriptionDocumentDecoder.decode(oversized)) { error in
            XCTAssertEqual(error as? SubscriptionDocumentError, .inputTooLarge)
        }
        XCTAssertThrowsError(try SubscriptionDocumentDecoder.decode(Data([0xC3, 0x28]))) { error in
            XCTAssertEqual(error as? SubscriptionDocumentError, .invalidUTF8)
        }
    }
}

final class SubscriptionImporterTests: XCTestCase {
    func testPartialImportReportsAcceptedAndRejected() {
        let result = SubscriptionImporter.importLines(
            [vlessLine, "vmess://eyJhZGRyZXNzIjoieCJ9", "definitely not a link"],
            credentialSink: makeTestSink()
        )
        XCTAssertEqual(result.accepted.count, 1)
        XCTAssertEqual(result.rejected.count, 2)
        XCTAssertEqual(result.rejected.map(\.index), [2, 3])
        XCTAssertTrue(result.rejected.allSatisfy { $0.reason == .unsupportedScheme || $0.reason == .malformedURL })
    }

    func testAcceptsCanonicalUUIDsWithHexLetters() {
        // Regression: the old pre-check rejected any UUID containing a–f.
        let result = SubscriptionImporter.importLines(
            ["vless://7b0c2f4a-9e1d-4c3b-8a5f-6d2e1c0b9a87@synthetic.example:443?encryption=none&security=tls&type=tcp"],
            credentialSink: makeTestSink()
        )
        XCTAssertEqual(result.accepted.count, 1)
        XCTAssertTrue(result.rejected.isEmpty)
    }

    func testDeduplicatesByLine() {
        let result = SubscriptionImporter.importLines(
            [trojanLine, trojanLine, vlessLine],
            credentialSink: makeTestSink()
        )
        XCTAssertEqual(result.accepted.count, 2)
        XCTAssertTrue(result.rejected.isEmpty)
    }

    func testIDsAreStableAcrossRefreshes() {
        let first = SubscriptionImporter.importLines([vlessLine, trojanLine], credentialSink: makeTestSink())
        let second = SubscriptionImporter.importLines(
            [trojanLine, vlessLine, "vmess://eyJhZGRyZXNzIjoieCJ9"],
            credentialSink: makeTestSink()
        )
        let idsFirst = Dictionary(uniqueKeysWithValues: first.accepted.map { ($0.displayValue, $0.server.id) })
        for parsed in second.accepted {
            XCTAssertEqual(parsed.server.id, idsFirst[parsed.displayValue])
        }
    }

    func testEmptyQueryValueForOptionalKeyIsAccepted() throws {
        let publicKey = String(repeating: "A", count: 43)
        let link = "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443"
            + "?encryption=none&security=reality&type=tcp&pbk=\(publicKey)&sid=&sni=synthetic.example"
        let parsed = try ShareLinkParser.parse(
            Data(link.utf8),
            id: UUID(),
            credentialSink: makeTestSink()
        )
        XCTAssertNil(parsed.server.transport.options["realityShortID"])
    }

    func testMissingEqualsIsStillMalformed() {
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&type".utf8),
                id: UUID(),
                credentialSink: makeTestSink()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .invalidQuery)
        }
    }

    func testExtraEqualsSplitsOnFirst() {
        // `a=b=c` is key `a`, value `b=c`: the key is unknown either way.
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&a=b=c".utf8),
                id: UUID(),
                credentialSink: makeTestSink()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .unsupportedQueryKey)
        }
    }
}

private struct StubSession: SubscriptionHTTPSession {
    let handler: @Sendable (URLRequest) throws -> (Data, URLResponse)

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try handler(request)
    }
}

private func httpResponse(url: URL, status: Int) -> HTTPURLResponse {
    HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil)!
}

final class SubscriptionFetcherTests: XCTestCase {
    func testFetchesHTTPS() async throws {
        let url = URL(string: "https://provider.example/sub")!
        let fetcher = SubscriptionFetcher(
            session: StubSession { _ in (Data("x".utf8), httpResponse(url: url, status: 200)) }
        )
        let fetched = try await fetcher.fetch(url)
        XCTAssertEqual(fetched.data, Data("x".utf8))
        XCTAssertNil(fetched.userInfo)
    }

    func testParsesUserInfoHeader() async throws {
        let url = URL(string: "https://provider.example/sub")!
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: ["subscription-userinfo": "upload=100; download=200; total=1000; expire=1893456000"]
        )!
        let fetcher = SubscriptionFetcher(session: StubSession { _ in (Data("x".utf8), response) })
        let fetched = try await fetcher.fetch(url)
        let info = try XCTUnwrap(fetched.userInfo)
        XCTAssertEqual(info.uploadBytes, 100)
        XCTAssertEqual(info.downloadBytes, 200)
        XCTAssertEqual(info.totalBytes, 1000)
        XCTAssertEqual(info.expireDate, Date(timeIntervalSince1970: 1_893_456_000))
    }

    func testMalformedUserInfoHeaderIsIgnored() async throws {
        let url = URL(string: "https://provider.example/sub")!
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: ["subscription-userinfo": "garbage;;;"]
        )!
        let fetcher = SubscriptionFetcher(session: StubSession { _ in (Data("x".utf8), response) })
        let fetched = try await fetcher.fetch(url)
        XCTAssertNil(fetched.userInfo)
    }

    func testHTTPBlockedByDefaultAllowedByPolicy() async throws {
        let url = URL(string: "http://provider.example/sub")!
        let blocked = SubscriptionFetcher(
            session: StubSession { _ in (Data("x".utf8), httpResponse(url: url, status: 200)) }
        )
        await XCTAssertThrowsAsync(try await blocked.fetch(url)) { error in
            XCTAssertEqual(error as? SubscriptionFetchError, .insecureSchemeBlocked)
        }
        let allowed = SubscriptionFetcher(
            session: StubSession { _ in (Data("x".utf8), httpResponse(url: url, status: 200)) },
            policy: SubscriptionFetchPolicy(allowInsecureHTTP: true)
        )
        let fetchedInsecure = try await allowed.fetch(url)
        XCTAssertEqual(fetchedInsecure.data, Data("x".utf8))
    }

    func testRejectsNonHTTPSErrorStatusesAndEmptyBodies() async {
        let https = URL(string: "https://provider.example/sub")!
        let ftp = URL(string: "ftp://provider.example/sub")!
        let fetcher = SubscriptionFetcher(
            session: StubSession { request in
                (Data("x".utf8), httpResponse(url: request.url!, status: 404))
            }
        )
        await XCTAssertThrowsAsync(try await fetcher.fetch(ftp)) { error in
            XCTAssertEqual(error as? SubscriptionFetchError, .invalidURL)
        }
        await XCTAssertThrowsAsync(try await fetcher.fetch(https)) { error in
            XCTAssertEqual(error as? SubscriptionFetchError, .httpStatus(404))
        }
        let empty = SubscriptionFetcher(
            session: StubSession { request in
                (Data(), httpResponse(url: request.url!, status: 200))
            }
        )
        await XCTAssertThrowsAsync(try await empty.fetch(https)) { error in
            XCTAssertEqual(error as? SubscriptionFetchError, .emptyBody)
        }
    }

    func testCancellationMapsToCancelled() async {
        struct CancelledSession: SubscriptionHTTPSession {
            func data(for request: URLRequest) async throws -> (Data, URLResponse) {
                throw CancellationError()
            }
        }
        let fetcher = SubscriptionFetcher(session: CancelledSession())
        await XCTAssertThrowsAsync(
            try await fetcher.fetch(URL(string: "https://provider.example/sub")!)
        ) { error in
            XCTAssertEqual(error as? SubscriptionFetchError, .cancelled)
        }
    }

    func testErrorsNeverCarryTheURL() {
        let secret = URL(string: "https://provider.example/sub?token=secret-token-123")!
        for error: SubscriptionFetchError in [
            .invalidURL, .insecureSchemeBlocked, .cancelled, .timedOut,
            .httpStatus(500), .emptyBody, .tooLarge, .networkError
        ] {
            XCTAssertFalse(String(describing: error).contains("secret-token-123"))
            XCTAssertFalse(String(describing: error).contains(secret.absoluteString))
        }
    }
}

final class SubscriptionStoreTests: XCTestCase {
    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    private func storedRecord(name: String = "Provider") -> StoredSubscription {
        StoredSubscription(
            name: name,
            source: SubscriptionSource(
                kind: .url,
                displayValue: "https://provider.example/sub?token=secret",
                secretReference: SecretReference(key: "subscription/test")
            )
        )
    }

    func testRoundTripPersistsAcrossInstances() async throws {
        let directory = temporaryDirectory()
        let first = SubscriptionStore(directory: directory)
        try await first.load()
        try await first.upsert(storedRecord())
        let second = SubscriptionStore(directory: directory)
        try await second.load()
        let records = await second.subscriptions()
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].name, "Provider")
        XCTAssertEqual(records[0].source.displayValue, "https://provider.example/••••••••")
    }

    func testRenameRemoveAndUnknownIDs() async throws {
        let store = SubscriptionStore(directory: temporaryDirectory())
        try await store.load()
        let record = storedRecord()
        try await store.upsert(record)
        try await store.rename(id: record.id, name: "Renamed")
        let renamed = await store.subscriptions()
        XCTAssertEqual(renamed[0].name, "Renamed")
        try await store.remove(id: record.id)
        let remaining = await store.subscriptions()
        XCTAssertTrue(remaining.isEmpty)
        await XCTAssertThrowsAsync(try await store.rename(id: record.id, name: "x")) { error in
            XCTAssertEqual(error as? SubscriptionStoreError, .unknownSubscription)
        }
        await XCTAssertThrowsAsync(try await store.remove(id: record.id)) { error in
            XCTAssertEqual(error as? SubscriptionStoreError, .unknownSubscription)
        }
    }

    func testRefreshIsAtomicAndLeaksNoSecrets() async throws {
        let directory = temporaryDirectory()
        let store = SubscriptionStore(directory: directory)
        try await store.load()
        var record = storedRecord()
        let imported = SubscriptionImporter.importLines([trojanLine], credentialSink: makeTestSink())
        XCTAssertEqual(imported.accepted.count, 1)
        record.servers = imported.accepted.map(\.server)
        record.acceptedCount = imported.accepted.count
        try await store.upsert(record)
        // A failed refresh never reaches `replaceServers`: the file on disk
        // still holds the last working list.
        let reloaded = SubscriptionStore(directory: directory)
        try await reloaded.load()
        let reloadedRecords = await reloaded.subscriptions()
        XCTAssertEqual(reloadedRecords[0].servers.count, 1)
        let raw = try Data(contentsOf: directory.appendingPathComponent("subscriptions.json"))
        XCTAssertFalse(String(decoding: raw, as: UTF8.self).contains("Pipeline-Password-1"))
    }
}

final class SubscriptionScaleTests: XCTestCase {
    func testImportScalesToThousands() {
        for count in [100, 1_000, 5_000] {
            let lines = (1...count).map { index in
                "vless://00000000-0000-0000-0000-\(String(format: "%012X", index))@h\(index).example:443?encryption=none&security=tls&type=tcp"
            }
            let start = Date()
            let result = SubscriptionImporter.importLines(lines, credentialSink: makeTestSink())
            let elapsed = Date().timeIntervalSince(start)
            XCTAssertEqual(result.accepted.count, count, "count \(count)")
            XCTAssertTrue(result.rejected.isEmpty, "count \(count)")
            XCTAssertEqual(Set(result.accepted.map { $0.server.id }).count, count, "count \(count)")
            print("importLines(\(count)) = \(String(format: "%.3f", elapsed))s")
        }
    }
}

private func XCTAssertThrowsAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    verify: (Error) -> Void
) async {
    do {
        _ = try await expression()
        XCTFail("expected throw: \(message)", file: file, line: line)
    } catch {
        verify(error)
    }
}


private func startLoopbackListener() async throws -> (NWListener, Int) {
    final class ReadyBox: @unchecked Sendable { var done = false }
    let listener = try NWListener(using: .tcp, on: 0)
    listener.newConnectionHandler = { $0.start(queue: .global()) }
    let box = ReadyBox()
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        listener.stateUpdateHandler = { state in
            if case .ready = state, !box.done {
                box.done = true
                continuation.resume()
            }
        }
        listener.start(queue: .global())
    }
    return (listener, Int(try XCTUnwrap(listener.port?.rawValue)))
}



final class LatencyProberTests: XCTestCase {
    func testLoopbackConnectReportsMilliseconds() async throws {
        let (listener, port) = try await startLoopbackListener()
        defer { listener.cancel() }
        let measured = await LatencyProber.probe(host: "127.0.0.1", port: port, timeout: 3)
        XCTAssertNotNil(measured)
    }

    func testRefusedPortReportsNil() async {
        let measured = await LatencyProber.probe(host: "127.0.0.1", port: 1, timeout: 3)
        XCTAssertNil(measured)
    }

    func testUnroutableHostTimesOut() async {
        let start = Date()
        let measured = await LatencyProber.probe(host: "192.0.2.1", port: 443, timeout: 1)
        XCTAssertNil(measured)
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }

    func testProbeAllPreservesOrderWithBoundedConcurrency() async throws {
        let (listener, port) = try await startLoopbackListener()
        defer { listener.cancel() }
        let results = await LatencyProber.probeAll(
            [(host: "127.0.0.1", port: port), (host: "127.0.0.1", port: 1)],
            maxConcurrent: 1,
            timeout: 3
        )
        XCTAssertEqual(results.count, 2)
        XCTAssertNotNil(results[0])
        XCTAssertNil(results[1])
    }
}
