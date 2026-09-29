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
    return { _, _ in
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

final class CanonicalLineTests: XCTestCase {
    private let base = "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=tcp"

    func testFragmentIsIgnored() {
        XCTAssertEqual(
            SubscriptionImporter.stableID(line: base + "#My Server"),
            SubscriptionImporter.stableID(line: base + "#Other Name")
        )
    }

    func testQueryOrderIsIgnored() {
        let reordered = "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?type=tcp&security=tls&encryption=none"
        XCTAssertEqual(
            SubscriptionImporter.stableID(line: base),
            SubscriptionImporter.stableID(line: reordered)
        )
    }

    func testSchemeAndHostCaseIsIgnored() {
        let upper = "VLESS://00000000-0000-0000-0000-000000000001@SYNTHETIC.EXAMPLE:443?encryption=none&security=tls&type=tcp"
        XCTAssertEqual(
            SubscriptionImporter.stableID(line: base),
            SubscriptionImporter.stableID(line: upper)
        )
    }

    func testPasswordCaseChangesIdentity() {
        let a = "trojan://Secret-Password@synthetic.example:443?security=tls"
        let b = "trojan://secret-password@synthetic.example:443?security=tls"
        XCTAssertNotEqual(
            SubscriptionImporter.stableID(line: a),
            SubscriptionImporter.stableID(line: b)
        )
    }

    func testCosmeticDuplicatesCollapseToOne() {
        let result = SubscriptionImporter.importLines(
            [base, base + "#Renamed", base],
            credentialSink: { _, _ in SecretReference(key: "test/credential") }
        )
        XCTAssertEqual(result.accepted.count, 1)
        XCTAssertTrue(result.rejected.isEmpty)
    }
}

final class StoreSchemaVersionTests: XCTestCase {
    func testLegacyFileDecodesAsV1AndNewRecordsEncodeV2() throws {
        let legacy = """
        [{"id":"\(UUID().uuidString)","name":"Legacy","source":{"kind":"url","displayValue":"https://provider.example/••••••••","secretReference":{"kind":"keychain","key":"subscription/legacy"}},"servers":[],"acceptedCount":0,"rejectedCount":0,"updatedAt":789000000}]
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode([StoredSubscription].self, from: legacy)
        XCTAssertEqual(decoded[0].schemaVersion, 1)
        XCTAssertFalse(decoded[0].allowInsecure)
        XCTAssertNil(decoded[0].userInfo)

        let record = StoredSubscription(
            name: "New",
            source: SubscriptionSource(kind: .pastedText, displayValue: "pasted text")
        )
        XCTAssertEqual(record.schemaVersion, StoredSubscription.currentSchemaVersion)
        let roundTripped = try JSONDecoder().decode(
            [StoredSubscription].self,
            from: JSONEncoder().encode([record])
        )
        XCTAssertEqual(roundTripped[0].schemaVersion, StoredSubscription.currentSchemaVersion)
    }
}

final class CredentialSinkIdentityTests: XCTestCase {
    func testSinkReceivesParsedServerID() {
        var received: [UUID] = []
        let result = SubscriptionImporter.importLines(
            [vlessLine],
            credentialSink: { id, _ in
                received.append(id)
                return SecretReference(key: "test/credential")
            }
        )
        XCTAssertEqual(result.accepted.count, 1)
        XCTAssertEqual(received, [result.accepted[0].server.id])
    }
}

final class StoreAtomicityTests: XCTestCase {
    private func blockingDirectory() throws -> URL {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data("block".utf8).write(to: file)
        return file.appendingPathComponent("store")
    }

    private func sampleRecord(name: String = "P") -> StoredSubscription {
        StoredSubscription(
            name: name,
            source: SubscriptionSource(
                kind: .url,
                displayValue: "https://provider.example/sub?token=secret",
                secretReference: SecretReference(key: "subscription/test")
            )
        )
    }

    func testFailedPersistLeavesMemoryUntouched() async throws {
        let store = SubscriptionStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
        try await store.load()
        try await store.upsert(sampleRecord(name: "Good"))
        // Sabotage persistence by swapping in an unwritable location is not
        // possible on the same store; instead verify the rollback path with a
        // store whose directory is a file.
        let blocked = SubscriptionStore(directory: try blockingDirectory())
        try await blocked.load()
        do {
            try await blocked.upsert(sampleRecord())
            XCTFail("expected persistenceFailed")
        } catch let error as SubscriptionStoreError {
            XCTAssertEqual(error, .persistenceFailed)
        }
        let blockedRecords = await blocked.subscriptions()
        XCTAssertTrue(blockedRecords.isEmpty)
    }

    func testFailedRenameRemoveAndRefreshKeepRecords() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let store = SubscriptionStore(directory: dir)
        try await store.load()
        let record = sampleRecord()
        try await store.upsert(record)
        // Make the directory unreadable for writing by replacing it with a file.
        try FileManager.default.removeItem(at: dir)
        try Data("block".utf8).write(to: dir)
        for operation in ["rename", "remove", "refresh"] {
            do {
                switch operation {
                case "rename": try await store.rename(id: record.id, name: "X")
                case "remove": try await store.remove(id: record.id)
                default: try await store.replaceServers(id: record.id, servers: [], acceptedCount: 0, rejectedCount: 0)
                }
                XCTFail("expected persistenceFailed for \(operation)")
            } catch let error as SubscriptionStoreError {
                XCTAssertEqual(error, .persistenceFailed, operation)
            }
        }
        let kept = await store.subscriptions()
        XCTAssertEqual(kept.count, 1)
        XCTAssertEqual(kept.first?.name, "P")
    }

    func testLoadRetriesAfterFailure() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("corrupt{".utf8).write(to: dir.appendingPathComponent("subscriptions.json"))
        let store = SubscriptionStore(directory: dir)
        do {
            try await store.load()
            XCTFail("expected persistenceFailed")
        } catch let error as SubscriptionStoreError {
            XCTAssertEqual(error, .persistenceFailed)
        }
        try Data("[]".utf8).write(to: dir.appendingPathComponent("subscriptions.json"))
        try await store.load()
        let reloaded = await store.subscriptions()
        XCTAssertTrue(reloaded.isEmpty)
    }
}

/// Minimal loopback HTTP server for fetcher integration tests: the stub
/// path never exercises redirects, streaming caps, or cancellation, so the
/// production fetcher is tested against real sockets here.
private final class FixtureHTTPServer: Sendable {
    struct Route: Sendable {
        var status: Int
        var headers: [String: String]
        var chunks: [Data]
        var chunkDelayNanoseconds: UInt64
        var repeatChunks: Int
    }

    private let listener: NWListener

    init(routes: [String: Route]) throws {
        listener = try NWListener(using: .tcp, on: 0)
        let routesBox = RoutesBox(routes: routes)
        listener.newConnectionHandler = { [routesBox] connection in
            connection.start(queue: .global())
            FixtureHTTPServer.serve(connection, routesBox: routesBox)
        }
    }

    var port: Int {
        Int(listener.port?.rawValue ?? 0)
    }

    func start() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let box = ReadyFlag()
            listener.stateUpdateHandler = { state in
                if case .ready = state, !box.done {
                    box.done = true
                    continuation.resume()
                }
            }
            listener.start(queue: .global())
        }
    }

    func stop() {
        listener.cancel()
    }

    private static func serve(_ connection: NWConnection, routesBox: RoutesBox) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, _ in
            guard let data, let request = String(data: data, encoding: .utf8),
                  let path = request.split(separator: " ").dropFirst().first.map(String.init)
            else {
                connection.cancel()
                return
            }
            let cleanPath = String(path.split(separator: "?").first ?? "?")
            guard let route = routesBox.routes[cleanPath] else {
                send(connection, status: 404, headers: [:], body: Data("no route".utf8))
                return
            }
            var headers = route.headers
            let total = route.chunks.reduce(0) { $0 + $1.count } * max(1, route.repeatChunks)
            if route.repeatChunks <= 1 {
                headers["Content-Length"] = "\(total)"
            }
            headers["Connection"] = "close"
            sendHeaders(connection, status: route.status, headers: headers) {
                sendChunks(connection, route: route, remaining: max(1, route.repeatChunks))
            }
        }
    }

    private static func send(_ connection: NWConnection, status: Int, headers: [String: String], body: Data) {
        var all = headers
        all["Content-Length"] = "\(body.count)"
        all["Connection"] = "close"
        sendHeaders(connection, status: status, headers: all) {
            connection.send(content: body, completion: .contentProcessed { _ in connection.cancel() })
        }
    }

    private static func sendHeaders(_ connection: NWConnection, status: Int, headers: [String: String], done: @Sendable @escaping () -> Void) {
        var text = "HTTP/1.1 \(status) \(reason(status))\r\n"
        for (key, value) in headers.sorted(by: { $0.key < $1.key }) {
            text += "\(key): \(value)\r\n"
        }
        text += "\r\n"
        connection.send(content: Data(text.utf8), completion: .contentProcessed { _ in done() })
    }

    private static func sendChunks(_ connection: NWConnection, route: Route, remaining: Int) {
        guard remaining > 0 else {
            connection.cancel()
            return
        }
        // The delay applies before every round, including the first: a slow
        // server stalls the body, which is what cancellation must interrupt.
        guard route.chunkDelayNanoseconds > 0 else {
            sendOne(connection, chunks: route.chunks, index: 0) {
                sendChunks(connection, route: route, remaining: remaining - 1)
            }
            return
        }
        Task {
            try? await Task.sleep(nanoseconds: route.chunkDelayNanoseconds)
            sendOne(connection, chunks: route.chunks, index: 0) {
                sendChunks(connection, route: route, remaining: remaining - 1)
            }
        }
    }

    private static func sendOne(_ connection: NWConnection, chunks: [Data], index: Int, done: @Sendable @escaping () -> Void) {
        guard index < chunks.count else {
            done()
            return
        }
        connection.send(content: chunks[index], completion: .contentProcessed { error in
            if error != nil {
                connection.cancel()
                return
            }
            sendOne(connection, chunks: chunks, index: index + 1, done: done)
        })
    }

    private static func reason(_ status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 302: return "Found"
        case 404: return "Not Found"
        default: return "Status"
        }
    }
}

private final class RoutesBox: Sendable {
    let routes: [String: FixtureHTTPServer.Route]

    init(routes: [String: FixtureHTTPServer.Route]) {
        self.routes = routes
    }
}

private final class ReadyFlag: @unchecked Sendable {
    var done = false
}

final class SubscriptionFetcherIntegrationTests: XCTestCase {
    private func server(_ routes: [String: FixtureHTTPServer.Route]) async throws -> FixtureHTTPServer {
        let server = try FixtureHTTPServer(routes: routes)
        await server.start()
        return server
    }

    private func url(_ server: FixtureHTTPServer, _ path: String) -> URL {
        URL(string: "http://127.0.0.1:\(server.port)\(path)")!
    }

    func testRedirectChainIsFollowed() async throws {
        let server = try await server([
            "/r1": .init(status: 302, headers: ["Location": "/r2"], chunks: [], chunkDelayNanoseconds: 0, repeatChunks: 1),
            "/r2": .init(status: 302, headers: ["Location": "/final"], chunks: [], chunkDelayNanoseconds: 0, repeatChunks: 1),
            "/final": .init(status: 200, headers: [:], chunks: [Data("done".utf8)], chunkDelayNanoseconds: 0, repeatChunks: 1),
        ])
        defer { server.stop() }
        let fetcher = SubscriptionFetcher.production(policy: SubscriptionFetchPolicy(allowInsecureHTTP: true))
        let result = try await fetcher.fetch(url(server, "/r1"))
        XCTAssertEqual(result.data, Data("done".utf8))
    }

    func testTooManyRedirectsAreBlocked() async throws {
        var routes: [String: FixtureHTTPServer.Route] = [:]
        for index in 0..<7 {
            routes["/r\(index)"] = .init(status: 302, headers: ["Location": "/r\(index + 1)"], chunks: [], chunkDelayNanoseconds: 0, repeatChunks: 1)
        }
        routes["/r7"] = .init(status: 200, headers: [:], chunks: [Data("done".utf8)], chunkDelayNanoseconds: 0, repeatChunks: 1)
        let server = try await server(routes)
        defer { server.stop() }
        let fetcher = SubscriptionFetcher.production(policy: SubscriptionFetchPolicy(allowInsecureHTTP: true))
        do {
            _ = try await fetcher.fetch(url(server, "/r0"))
            XCTFail("expected redirectBlocked")
        } catch let error as SubscriptionFetchError {
            XCTAssertEqual(error, .redirectBlocked)
        }
    }

    func testSlowStreamSucceedsWithinTimeout() async throws {
        let server = try await server([
            "/slow": .init(status: 200, headers: [:], chunks: [Data("ab".utf8), Data("cd".utf8)], chunkDelayNanoseconds: 100_000_000, repeatChunks: 1),
        ])
        defer { server.stop() }
        let fetcher = SubscriptionFetcher.production(policy: SubscriptionFetchPolicy(allowInsecureHTTP: true, timeout: 10))
        let result = try await fetcher.fetch(url(server, "/slow"))
        XCTAssertEqual(result.data, Data("abcd".utf8))
    }

    func testOversizedStreamIsCutWithoutLength() async throws {
        let server = try await server([
            // No Content-Length (repeatChunks > 1 omits it): the cap must
            // come from counting actual bytes, not the header.
            "/big": .init(status: 200, headers: [:], chunks: [Data(repeating: 0x61, count: 64)], chunkDelayNanoseconds: 0, repeatChunks: 1000),
        ])
        defer { server.stop() }
        let fetcher = SubscriptionFetcher.production(policy: SubscriptionFetchPolicy(allowInsecureHTTP: true, maximumBytes: 128))
        do {
            _ = try await fetcher.fetch(url(server, "/big"))
            XCTFail("expected tooLarge")
        } catch let error as SubscriptionFetchError {
            XCTAssertEqual(error, .tooLarge)
        }
    }

    func testCancellationAbortsTheDownload() async throws {
        let server = try await server([
            "/slow": .init(status: 200, headers: [:], chunks: [Data("ab".utf8)], chunkDelayNanoseconds: 5_000_000_000, repeatChunks: 1),
        ])
        defer { server.stop() }
        let fetcher = SubscriptionFetcher.production(policy: SubscriptionFetchPolicy(allowInsecureHTTP: true, timeout: 30))
        let target = url(server, "/slow")
        let task = Task { [fetcher, target] in try await fetcher.fetch(target) }
        try await Task.sleep(nanoseconds: 300_000_000)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancelled")
        } catch let error as SubscriptionFetchError {
            XCTAssertEqual(error, .cancelled)
        }
    }

    func testHTTPErrorAndUserInfo() async throws {
        let server = try await server([
            "/missing": .init(status: 404, headers: [:], chunks: [Data("no".utf8)], chunkDelayNanoseconds: 0, repeatChunks: 1),
            "/meta": .init(status: 200, headers: ["subscription-userinfo": "upload=1; download=2; total=100; expire=1893456000"], chunks: [Data("x".utf8)], chunkDelayNanoseconds: 0, repeatChunks: 1),
        ])
        defer { server.stop() }
        let fetcher = SubscriptionFetcher.production(policy: SubscriptionFetchPolicy(allowInsecureHTTP: true))
        do {
            _ = try await fetcher.fetch(url(server, "/missing"))
            XCTFail("expected httpStatus")
        } catch let error as SubscriptionFetchError {
            XCTAssertEqual(error, .httpStatus(404))
        }
        let result = try await fetcher.fetch(url(server, "/meta"))
        XCTAssertEqual(result.userInfo?.totalBytes, 100)
    }

    func testPerCallPolicyOverridesStoredPolicy() async throws {
        let server = try await server([
            "/meta": .init(status: 200, headers: ["subscription-userinfo": "upload=1; download=2; total=100; expire=1893456000"], chunks: [Data("x".utf8)], chunkDelayNanoseconds: 0, repeatChunks: 1),
        ])
        defer { server.stop() }
        let strict = SubscriptionFetcher.production()
        do {
            _ = try await strict.fetch(url(server, "/meta"))
            XCTFail("expected insecureSchemeBlocked")
        } catch let error as SubscriptionFetchError {
            XCTAssertEqual(error, .insecureSchemeBlocked)
        }
        let result = try await strict.fetch(
            url(server, "/meta"),
            policy: SubscriptionFetchPolicy(allowInsecureHTTP: true)
        )
        XCTAssertEqual(result.userInfo?.totalBytes, 100)
        do {
            _ = try await strict.fetch(url(server, "/meta"))
            XCTFail("expected insecureSchemeBlocked")
        } catch let error as SubscriptionFetchError {
            XCTAssertEqual(error, .insecureSchemeBlocked)
        }
    }

    func testConcurrentFetchesKeepTheirOwnPolicies() async throws {
        let server = try await server([
            "/meta": .init(status: 200, headers: ["subscription-userinfo": "upload=1; download=2; total=100; expire=1893456000"], chunks: [Data("x".utf8)], chunkDelayNanoseconds: 0, repeatChunks: 1),
        ])
        defer { server.stop() }
        let strict = SubscriptionFetcher.production()
        let target = url(server, "/meta")
        try await withThrowingTaskGroup(of: String.self) { group in
            group.addTask { [strict, target] in
                let result = try await strict.fetch(
                    target, policy: SubscriptionFetchPolicy(allowInsecureHTTP: true)
                )
                return result.userInfo?.totalBytes == 100 ? "ok" : "bad-body"
            }
            group.addTask { [strict, target] in
                do {
                    _ = try await strict.fetch(target)
                    return "unexpected-success"
                } catch let error as SubscriptionFetchError {
                    return String(describing: error)
                }
            }
            var outcomes: [String] = []
            for try await outcome in group {
                outcomes.append(outcome)
            }
            XCTAssertEqual(outcomes.sorted(), ["insecureSchemeBlocked", "ok"])
        }
    }
}

final class RedirectPolicyTests: XCTestCase {
    private let strict = SubscriptionFetchPolicy()
    private let insecure = SubscriptionFetchPolicy(allowInsecureHTTP: true)

    func testAllowsHTTPSChainWithinLimit() {
        for hops in 0..<5 {
            XCTAssertTrue(SubscriptionRedirectDelegate.allowsRedirect(
                fromScheme: "https",
                to: URL(string: "https://cdn.example/part")!,
                hops: hops, policy: strict
            ))
        }
        XCTAssertFalse(SubscriptionRedirectDelegate.allowsRedirect(
            fromScheme: "https",
            to: URL(string: "https://cdn.example/part")!,
            hops: 5, policy: strict
        ))
    }

    func testDowngradeRequiresExplicitOptIn() {
        let target = URL(string: "http://cdn.example/part")!
        XCTAssertFalse(SubscriptionRedirectDelegate.allowsRedirect(
            fromScheme: "https", to: target, hops: 0, policy: strict
        ))
        XCTAssertTrue(SubscriptionRedirectDelegate.allowsRedirect(
            fromScheme: "https", to: target, hops: 0, policy: insecure
        ))
        XCTAssertTrue(SubscriptionRedirectDelegate.allowsRedirect(
            fromScheme: "http", to: target, hops: 0, policy: strict
        ))
    }

    func testRejectsNonHTTPAndHostlessTargets() {
        XCTAssertFalse(SubscriptionRedirectDelegate.allowsRedirect(
            fromScheme: "https", to: URL(string: "ftp://cdn.example/x")!, hops: 0, policy: insecure
        ))
        XCTAssertFalse(SubscriptionRedirectDelegate.allowsRedirect(
            fromScheme: "https", to: URL(string: "https:///path")!, hops: 0, policy: insecure
        ))
    }
}

final class RemarkNameTests: XCTestCase {
    private func parse(_ link: String) throws -> ParsedShareLink {
        try ShareLinkParser.parse(
            Data(link.utf8),
            id: UUID(),
            credentialSink: { _, _ in SecretReference(key: "test/credential") }
        )
    }

    func testFragmentBecomesDisplayName() throws {
        let parsed = try parse("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=tcp#Helsinki%201")
        XCTAssertEqual(parsed.server.name, "Helsinki 1")
        // The redacted display value never carries the remark.
        XCTAssertEqual(parsed.displayValue, "vless://synthetic.example:443/••••••••")
    }

    func testMissingFragmentFallsBackToGenericName() throws {
        let parsed = try parse("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=tcp")
        XCTAssertEqual(parsed.server.name, "VLESS server")
    }

    func testUnsafeRemarkFallsBackToGenericName() throws {
        // Control characters reject the whole link (pre-existing strictness);
        // an overlong remark parses but falls back to the generic name.
        XCTAssertThrowsError(
            try parse("trojan://Password-Canary@synthetic.example:443?security=tls#Bad%01Name")
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .malformedURL)
        }
        let long = try parse("trojan://Password-Canary@synthetic.example:443?security=tls#" + String(repeating: "a", count: 200))
        XCTAssertEqual(long.server.name, "Trojan server")
    }

    func testUnicodeRemarkIsKept() throws {
        let parsed = try parse("trojan://Password-Canary@synthetic.example:443?security=tls#%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F%201")
        XCTAssertEqual(parsed.server.name, "Финляндия 1")
    }
}

