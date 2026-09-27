import Foundation
import XCTest
@testable import RoviaConfig
@testable import RoviaSubscription

final class ShareLinkParserTests: XCTestCase {
    private let serverID = UUID(uuidString: "00000000-0000-0000-0000-000000000201")!

    func testParsesVLESSFixtureIntoCanonicalServerAndRedactedMetadata() throws {
        let recorder = CredentialRecorder()
        let parsed = try ShareLinkParser.parse(
            try fixtureData("vless-share-link.txt"),
            id: serverID,
            credentialSink: recorder.sink(referenceKey: "server/vless/credential"),
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(parsed.server.id, serverID)
        XCTAssertEqual(parsed.server.name, "VLESS server")
        XCTAssertEqual(parsed.server.protocolKind, .vless)
        XCTAssertEqual(parsed.server.endpoint, Endpoint(host: "synthetic.example", port: 443))
        XCTAssertEqual(parsed.server.credential, SecretReference(key: "server/vless/credential"))
        XCTAssertEqual(parsed.server.transport, TransportOptions(kind: "ws", options: ["host": "synthetic.example"]))
        XCTAssertEqual(parsed.server.tls, TLSOptions(serverName: "synthetic.example"))
        XCTAssertEqual(parsed.server.tags, ["share-link", "vless"])
        XCTAssertEqual(parsed.displayValue, "vless://synthetic.example:443/••••••••")
        XCTAssertEqual(parsed.secretReference, SecretReference(key: "server/vless/credential"))
        XCTAssertEqual(recorder.values, [Data("00000000-0000-0000-0000-000000000001".utf8)])
    }

    func testParsesTrojanFixtureIntoCanonicalServerAndRedactedMetadata() throws {
        let recorder = CredentialRecorder()
        let parsed = try ShareLinkParser.parse(
            try fixtureData("trojan-share-link.txt"),
            id: serverID,
            credentialSink: recorder.sink(referenceKey: "server/trojan/credential"),
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(parsed.server.id, serverID)
        XCTAssertEqual(parsed.server.name, "Trojan server")
        XCTAssertEqual(parsed.server.protocolKind, .trojan)
        XCTAssertEqual(parsed.server.endpoint, Endpoint(host: "synthetic.example", port: 443))
        XCTAssertEqual(parsed.server.credential, SecretReference(key: "server/trojan/credential"))
        XCTAssertEqual(parsed.server.transport, TransportOptions(kind: "tcp"))
        XCTAssertEqual(parsed.server.tls, TLSOptions(serverName: "synthetic.example"))
        XCTAssertEqual(parsed.server.tags, ["share-link", "trojan"])
        XCTAssertEqual(parsed.displayValue, "trojan://synthetic.example:443/••••••••")
        XCTAssertEqual(recorder.values, [Data("Trojan-Password-Canary".utf8)])
    }

    func testParsesShadowsocksSIP002FixtureWithoutExposingUserinfo() throws {
        let recorder = CredentialRecorder()
        let parsed = try ShareLinkParser.parse(
            try fixtureData("shadowsocks-share-link.txt"),
            id: serverID,
            credentialSink: recorder.sink(referenceKey: "server/shadowsocks/credential"),
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(parsed.server.id, serverID)
        XCTAssertEqual(parsed.server.name, "Shadowsocks server")
        XCTAssertEqual(parsed.server.protocolKind, .shadowsocks)
        XCTAssertEqual(parsed.server.endpoint, Endpoint(host: "synthetic.example", port: 8388))
        XCTAssertEqual(parsed.server.credential, SecretReference(key: "server/shadowsocks/credential"))
        XCTAssertEqual(
            parsed.server.transport,
            TransportOptions(kind: "tcp", options: ["method": "aes-256-gcm"])
        )
        XCTAssertNil(parsed.server.tls)
        XCTAssertEqual(parsed.server.tags, ["share-link", "shadowsocks"])
        XCTAssertEqual(parsed.displayValue, "ss://synthetic.example:8388/••••••••")
        XCTAssertEqual(recorder.values, [Data("Shadowsocks-Password-Canary".utf8)])
    }

    func testParsesPercentEncodedPlainSIP002AEADUserinfo() throws {
        let recorder = CredentialRecorder()
        let parsed = try ShareLinkParser.parse(
            Data("ss://aes-128-gcm:Plain%20Password%2BCanary@synthetic.example:8388#Fragment-Canary".utf8),
            id: serverID,
            credentialSink: recorder.sink(referenceKey: "server/shadowsocks/credential"),
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(parsed.server.transport, TransportOptions(kind: "tcp", options: ["method": "aes-128-gcm"]))
        XCTAssertNil(parsed.server.tls)
        XCTAssertEqual(recorder.values, [Data("Plain Password+Canary".utf8)])
        let json = String(decoding: try JSONCoding.encoder().encode(parsed), as: UTF8.self)
        XCTAssertFalse(json.contains("Plain"), "plain credential canary leaked")
        XCTAssertFalse(json.contains("Fragment-Canary"), "fragment canary leaked")
        XCTAssertFalse(json.contains("ss://aes-128-gcm:"), "raw SIP002 authority leaked")
    }

    func testParsesPlainSIP002AEADUserinfoWithOnlyUnreservedCharacters() throws {
        let recorder = CredentialRecorder()
        let parsed = try ShareLinkParser.parse(
            Data("ss://aes-128-gcm:password@synthetic.example:8388".utf8),
            id: serverID,
            credentialSink: recorder.sink(referenceKey: "server/shadowsocks/credential"),
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(parsed.server.transport, TransportOptions(kind: "tcp", options: ["method": "aes-128-gcm"]))
        XCTAssertEqual(recorder.values, [Data("password".utf8)])
    }

    func testRejectsMalformedPercentEncodedPlainSIP002Userinfo() {
        let cases: [(String, ShareLinkParseError)] = [
            ("ss://aes-128-gcm:%GG@synthetic.example:8388", .invalidPercentEncoding),
            ("ss://aes-128-gcm:%FF@synthetic.example:8388", .invalidPercentEncoding),
            ("ss://aes-128-gcm:%00@synthetic.example:8388", .invalidCredential),
            ("ss://aes-128-gcm:password:extra@synthetic.example:8388", .invalidCredential),
            ("ss://aes-128-gcm%3Apassword@synthetic.example:8388", .invalidCredential)
        ]

        for (index, testCase) in cases.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(testCase.0.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, testCase.1, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testRealityRequiresTCPAndTLSMetadata() throws {
        let publicKey = String(repeating: "A", count: 43)
        let parsed = try ShareLinkParser.parse(
            Data("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=reality&type=tcp&pbk=\(publicKey)&sid=00&sni=synthetic.example&fp=chrome&flow=xtls-rprx-vision".utf8),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/vless/credential") },
            limits: ShareLinkLimits()
        )
        XCTAssertEqual(parsed.server.transport.kind, "tcp")
        XCTAssertEqual(parsed.server.transport.options["realityPublicKey"], publicKey)
        XCTAssertNotNil(parsed.server.tls)

        let recorder = CredentialRecorder()
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=reality&type=ws&pbk=\(publicKey)&sni=synthetic.example".utf8),
                id: serverID,
                credentialSink: recorder.sink(),
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .unsupportedQueryValue)
        }
        XCTAssertTrue(recorder.values.isEmpty)
    }

    func testFlowRequiresTLSMetadata() throws {
        let insecureRecorder = CredentialRecorder()
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&type=tcp&flow=xtls-rprx-vision".utf8),
                id: serverID,
                credentialSink: insecureRecorder.sink(),
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .unsupportedQueryValue)
        }
        XCTAssertTrue(insecureRecorder.values.isEmpty)

        let parsed = try ShareLinkParser.parse(
            Data("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=ws&flow=xtls-rprx-vision".utf8),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/vless/credential") },
            limits: ShareLinkLimits()
        )
        XCTAssertNotNil(parsed.server.tls)
    }

    func testRealityOptionsAreRejectedWithoutTLSMode() {
        let publicKey = String(repeating: "A", count: 43)
        let links = [
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=none&pbk=\(publicKey)",
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&pbk=\(publicKey)",
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=none&sid=00"
        ]

        for (index, link) in links.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(link.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, .unsupportedQueryValue, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testCanonicalizesTrailingDotDNSBeforeOutputBounds() throws {
        let parsed = try ShareLinkParser.parse(
            Data("trojan://Trailing-Canary@synthetic.example.:443?security=tls".utf8),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/trailing/credential") },
            limits: ShareLinkLimits()
        )
        let json = String(decoding: try JSONCoding.encoder().encode(parsed), as: UTF8.self)

        XCTAssertEqual(parsed.server.endpoint.host, "synthetic.example")
        XCTAssertEqual(parsed.displayValue, "trojan://synthetic.example:443/••••••••")
        XCTAssertTrue(json.contains("\"host\":\"synthetic.example\""))
        XCTAssertFalse(json.contains("synthetic.example.:443"))
    }

    func testVLESSWithoutTLSIsRejected() {
        let recorder = CredentialRecorder()
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=none".utf8),
                id: serverID,
                credentialSink: recorder.sink(),
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .unsupportedQueryValue)
        }
        XCTAssertTrue(recorder.values.isEmpty)
    }

    func testParsesCanonicalServiceNameAndAllowInsecureQueryKeys() throws {
        let parsed = try ShareLinkParser.parse(
            Data("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=grpc&serviceName=canonical-worker&allowInsecure=1".utf8),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/vless/credential") },
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(parsed.server.transport, TransportOptions(kind: "grpc", options: ["serviceName": "canonical-worker"]))
        XCTAssertEqual(parsed.server.tls?.allowInsecure, true)
    }

    func testCanonicalServiceNamePredicateAndGRPCParserRejectSlashForms() {
        XCTAssertFalse(CanonicalParsedShareLinkRules.isServiceName("a/b"))
        XCTAssertFalse(CanonicalParsedShareLinkRules.isServiceName("a%2Fb"))

        let cases = [
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=grpc&serviceName=a/b",
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=grpc&serviceName=a%2Fb",
            "trojan://Trojan-Password-Canary@synthetic.example:443?security=tls&type=grpc&serviceName=a/b",
            "trojan://Trojan-Password-Canary@synthetic.example:443?security=tls&type=grpc&serviceName=a%2Fb"
        ]

        for (index, link) in cases.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(link.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, .invalidQuery, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testRejectsDuplicateAndConflictingCanonicalQueryKeys() {
        let cases: [(String, ShareLinkParseError)] = [
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=grpc&serviceName=one&serviceName=two", .duplicateQueryKey),
            ("trojan://Trojan-Password-Canary@synthetic.example:443?security=tls&allowInsecure=0&allowInsecure=1", .duplicateQueryKey),
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=ws&serviceName=one", .unsupportedQueryValue),
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=none&allowInsecure=1", .unsupportedQueryValue),
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&security=tls&type=grpc&ServiceName=one", .invalidQuery)
        ]

        for (index, testCase) in cases.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(testCase.0.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, testCase.1, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testParsingIsDeterministicForTheSameInputAndIdentifier() throws {
        let data = try fixtureData("vless-share-link.txt")
        let first = try ShareLinkParser.parse(
            data,
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/fixed") },
            limits: ShareLinkLimits()
        )
        let second = try ShareLinkParser.parse(
            data,
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/fixed") },
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(first, second)
    }

    func testRejectsDuplicateDecodedQueryKeysBeforeUsingCredentialSink() throws {
        let cases = [
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&t%79pe=tcp&type=ws",
            "trojan://Trojan-Password-Canary@synthetic.example:443?security=tls&sni=one.example&sni=two.example",
            "ss://YWVzLTI1Ni1nY206cGFzcw@synthetic.example:8388?plugin=one&plugin=two"
        ]

        for (index, link) in cases.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(link.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, .duplicateQueryKey, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testRejectsInvalidAndMissingPortsWithoutUsingCredentialSink() throws {
        let links = [
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:0",
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:0443",
            "vless://00000000-0000-0000-0000-000000000001@synthetic.example:65536",
            "trojan://Trojan-Password-Canary@synthetic.example:not-a-port",
            "ss://YWVzLTI1Ni1nY206cGFzcw@synthetic.example"
        ]

        for (index, link) in links.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(link.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, .invalidPort, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testRejectsBracketedDNSAndIllegalRawUserinfoDelimiters() {
        let cases: [(String, ShareLinkParseError)] = [
            ("vless://00000000-0000-0000-0000-000000000001@[synthetic.example]:443?encryption=none", .invalidHost),
            ("trojan://Trojan-Password-Canary@[192.0.2.1]:443?security=tls", .invalidHost),
            ("trojan://Trojan[Password@synthetic.example:443?security=tls", .invalidCredential),
            ("trojan://Trojan]Password@synthetic.example:443?security=tls", .invalidCredential),
            ("trojan://Trojan/Password@synthetic.example:443?security=tls", .invalidCredential),
            ("trojan://Trojan?Password@synthetic.example:443?security=tls", .malformedURL),
            ("trojan://Trojan#Password@synthetic.example:443?security=tls", .invalidCredential)
        ]

        for (index, testCase) in cases.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(testCase.0.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, testCase.1, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testAcceptsBracketedIPv6Authority() throws {
        let parsed = try ShareLinkParser.parse(
            Data("trojan://Boundary-Canary@[2001:db8::1]:443?security=tls".utf8),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/trojan/credential") },
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(parsed.server.endpoint, Endpoint(host: "2001:db8::1", port: 443))
    }

    func testRejectsMalformedAndUnsupportedLinksWithTypedErrors() throws {
        let cases: [(String, ShareLinkParseError)] = [
            ("", .emptyInput),
            ("vless://", .malformedURL),
            ("vmess://00000000-0000-0000-0000-000000000001@synthetic.example:443", .unsupportedScheme),
            ("vless://not-a-uuid@synthetic.example:443?encryption=none", .invalidUUID),
            ("vless://00000000-0000-0000-0000-000000000000@synthetic.example:443?encryption=none", .invalidUUID),
            ("vless://@synthetic.example:443?encryption=none", .invalidCredential),
            ("trojan://@synthetic.example:443?security=tls", .invalidCredential),
            ("vless://00000000-0000-0000-0000-000000000001@:443?encryption=none", .invalidHost),
            ("vless://00000000-0000-0000-0000-000000000001@999.999.999.999:443?encryption=none", .invalidHost),
            ("vless://00000000-0000-0000-0000-000000000001@192.168.001.1:443?encryption=none", .invalidHost),
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443/extra?encryption=none", .invalidPath),
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&&type=tcp", .invalidQuery),
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&type", .invalidQuery),
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none&token=Query-Canary", .unsupportedQueryKey),
            ("trojan://Trojan%ZZ-Password@synthetic.example:443", .invalidPercentEncoding),
            ("vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none#Fragment%ZZ", .invalidPercentEncoding),
            (" vless://00000000-0000-0000-0000-000000000001@synthetic.example:443?encryption=none", .malformedURL)
        ]

        for (index, testCase) in cases.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(testCase.0.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, testCase.1, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testRejectsNoncanonicalSIP002Userinfo() throws {
        let links = [
            "ss://not-base64@synthetic.example:8388",
            "ss://YWVzLTI1Ni1nY206@synthetic.example:8388",
            "ss://YWVzLTI1Ni1nYzpwYXNzd29yZA==@synthetic.example:8388",
            "ss://YWVzLTI1Ni1nY206cGFzcw=@synthetic.example:8388",
            "ss://YWVzLTEyOC1nY206cB@synthetic.example:8388"
        ]

        for (index, link) in links.enumerated() {
            let recorder = CredentialRecorder()
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(link.utf8),
                    id: serverID,
                    credentialSink: recorder.sink(),
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                XCTAssertEqual(error as? ShareLinkParseError, .invalidCredential, "case \(index)")
            }
            XCTAssertTrue(recorder.values.isEmpty, "case \(index)")
        }
    }

    func testPercentDecodesTrojanPasswordWithoutTreatingPlusAsSpace() throws {
        let recorder = CredentialRecorder()
        let parsed = try ShareLinkParser.parse(
            Data("trojan://Trojan%20Password+Canary@synthetic.example:443?security=tls#Trojan-Fragment-Canary".utf8),
            id: serverID,
            credentialSink: recorder.sink(referenceKey: "server/trojan/credential"),
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(recorder.values, [Data("Trojan Password+Canary".utf8)])
        XCTAssertEqual(parsed.server.name, "Trojan server")
        XCTAssertFalse(parsed.displayValue.contains("Fragment"))
    }

    func testTrojanSNIAndPeerAliasesAllowOnlyIdenticalValues() throws {
        let recorder = CredentialRecorder()
        let parsed = try ShareLinkParser.parse(
            Data("trojan://Alias-Canary@synthetic.example:443?security=tls&sni=alias.example&peer=alias.example".utf8),
            id: serverID,
            credentialSink: recorder.sink(referenceKey: "server/trojan/credential"),
            limits: ShareLinkLimits()
        )
        XCTAssertEqual(parsed.server.tls?.serverName, "alias.example")
        XCTAssertEqual(recorder.values.count, 1)

        let conflictingRecorder = CredentialRecorder()
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("trojan://Alias-Canary@synthetic.example:443?security=tls&sni=one.example&peer=two.example".utf8),
                id: serverID,
                credentialSink: conflictingRecorder.sink(),
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .invalidQuery)
        }
        XCTAssertTrue(conflictingRecorder.values.isEmpty)
    }

    func testRejectsOversizedInputAtCanonicalAndCustomLimits() throws {
        let oversized = Data(repeating: 0x61, count: ShareLinkLimits.maximumBytes + 1)
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                oversized,
                id: serverID,
                credentialSink: { _ in SecretReference(key: "server/unused") },
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .inputTooLarge)
        }

        let fixture = try fixtureData("trojan-share-link.txt")
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                fixture,
                id: serverID,
                credentialSink: { _ in SecretReference(key: "server/unused") },
                limits: ShareLinkLimits(maximumBytes: fixture.count - 1)
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .inputTooLarge)
        }
    }

    func testRejectsInvalidUTF8BeforeUsingCredentialSink() {
        let recorder = CredentialRecorder()

        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data([0xC3, 0x28]),
                id: serverID,
                credentialSink: recorder.sink(),
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .invalidUTF8)
        }
        XCTAssertTrue(recorder.values.isEmpty)
    }

    func testEncodedResultsAndErrorsDoNotContainCredentialOrURLCanaries() throws {
        let fixtureNames = [
            "vless-share-link.txt",
            "trojan-share-link.txt",
            "shadowsocks-share-link.txt"
        ]
        let forbidden = [
            "00000000-0000-0000-0000-000000000001",
            "Trojan-Password-Canary",
            "Shadowsocks-Password-Canary",
            "YWVzLTI1Ni1nY206U2hhZG93c29ja3MtUGFzc3dvcmQtQ2FuYXJ5",
            "Fragment-Canary",
            "encryption=none",
            "security=tls",
            "plugin="
        ]

        for fixtureName in fixtureNames {
            let data = try fixtureData(fixtureName)
            let rawLink = try XCTUnwrap(String(data: data, encoding: .utf8))
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let parsed = try ShareLinkParser.parse(
                data,
                id: serverID,
                credentialSink: { _ in SecretReference(key: "server/redacted") },
                limits: ShareLinkLimits()
            )
            let encoded = try JSONCoding.encoder().encode(parsed)
            let json = String(decoding: encoded, as: UTF8.self)

            XCTAssertFalse(json.contains(rawLink), fixtureName)
            for canary in forbidden {
                XCTAssertFalse(json.contains(canary), fixtureName)
            }
        }

        let malformedLinks = [
            "vless://UUID-Canary@synthetic.example:70000?token=Query-Canary#Fragment-Canary",
            "trojan://Trojan-Password-Canary@synthetic.example:443?security=tls&security=tls#Fragment-Canary",
            "ss://not-base64-Password-Canary@synthetic.example:8388?plugin=Plugin-Canary#Fragment-Canary"
        ]
        for (index, link) in malformedLinks.enumerated() {
            XCTAssertThrowsError(
                try ShareLinkParser.parse(
                    Data(link.utf8),
                    id: serverID,
                    credentialSink: { _ in SecretReference(key: "server/unused") },
                    limits: ShareLinkLimits()
                ),
                "case \(index)"
            ) { error in
                let renderings = [
                    String(describing: error),
                    String(reflecting: error),
                    error.localizedDescription
                ]
                for rendering in renderings {
                    XCTAssertFalse(rendering.contains("Canary"), "error rendering leaked credential canary")
                }
            }
        }
    }

    func testParsedShareLinkCodableAcceptsCanonicalParserResults() throws {
        for fixtureName in ["vless-share-link.txt", "trojan-share-link.txt", "shadowsocks-share-link.txt"] {
            let parsed = try ShareLinkParser.parse(
                try fixtureData(fixtureName),
                id: serverID,
                credentialSink: { _ in SecretReference(key: "server/contract/credential") },
                limits: ShareLinkLimits()
            )
            let data = try JSONCoding.encoder().encode(parsed)
            XCTAssertEqual(try JSONCoding.decoder().decode(ParsedShareLink.self, from: data), parsed)
        }
    }

    func testParserProducedParsedShareLinkFixtureMatchesCanonicalEncoding() throws {
        let parsed = try ShareLinkParser.parse(
            try fixtureData("vless-share-link.txt"),
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000201")!,
            credentialSink: { _ in SecretReference(key: "server/vless/credential") },
            limits: ShareLinkLimits()
        )
        let encoded = try JSONCoding.encoder().encode(parsed)
        let fixture = try Data(contentsOf: repositoryRoot
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("subscriptions", isDirectory: true)
            .appendingPathComponent("parsed-share-link.json"))
        XCTAssertEqual(
            String(decoding: encoded, as: UTF8.self),
            String(decoding: fixture, as: UTF8.self)
        )
    }

    func testParsedShareLinkCodableRejectsContractMismatches() throws {
        let vless = try ShareLinkParser.parse(
            try fixtureData("vless-share-link.txt"),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/contract/credential") },
            limits: ShareLinkLimits()
        )
        let trojan = try ShareLinkParser.parse(
            try fixtureData("trojan-share-link.txt"),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/contract/credential") },
            limits: ShareLinkLimits()
        )
        let shadowsocks = try ShareLinkParser.parse(
            try fixtureData("shadowsocks-share-link.txt"),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/contract/credential") },
            limits: ShareLinkLimits()
        )
        let base = try jsonObject(vless)
        let trojanBase = try jsonObject(trojan)
        let shadowsocksBase = try jsonObject(shadowsocks)
        var invalidObjects: [(String, [String: Any])] = []

        var wrongName = base
        try mutateServer(&wrongName) { $0["name"] = "Trojan server" }
        invalidObjects.append(("wrong protocol name", wrongName))

        var wrongTags = base
        try mutateServer(&wrongTags) { $0["tags"] = ["share-link", "trojan"] }
        invalidObjects.append(("wrong protocol tag", wrongTags))

        var wrongProtocol = base
        try mutateServer(&wrongProtocol) { $0["protocolKind"] = "trojan" }
        invalidObjects.append(("wrong protocol kind", wrongProtocol))

        var pathOnTCP = base
        try mutateServer(&pathOnTCP) {
            $0["transport"] = ["kind": "tcp", "options": ["path": "/invalid"]]
        }
        invalidObjects.append(("path on tcp", pathOnTCP))

        var flowWithoutTLS = base
        try mutateServer(&flowWithoutTLS) {
            $0["transport"] = ["kind": "tcp", "options": ["flow": "xtls-rprx-vision"]]
            $0["tls"] = NSNull()
        }
        invalidObjects.append(("flow without TLS", flowWithoutTLS))

        var vlessWithoutTLS = base
        try mutateServer(&vlessWithoutTLS) { $0["tls"] = NSNull() }
        invalidObjects.append(("vless without TLS", vlessWithoutTLS))

        let publicKey = String(repeating: "A", count: 43)

        var realityWithoutTLS = base
        try mutateServer(&realityWithoutTLS) {
            $0["transport"] = ["kind": "tcp", "options": ["realityPublicKey": publicKey]]
            $0["tls"] = NSNull()
        }
        invalidObjects.append(("reality without TLS", realityWithoutTLS))

        var realityOnWebSocket = base
        try mutateServer(&realityOnWebSocket) {
            $0["transport"] = ["kind": "ws", "options": ["realityPublicKey": publicKey]]
        }
        invalidObjects.append(("reality on websocket", realityOnWebSocket))

        var methodOnVLESS = base
        try mutateServer(&methodOnVLESS) {
            $0["transport"] = ["kind": "tcp", "options": ["method": "aes-128-gcm"]]
        }
        invalidObjects.append(("method on vless", methodOnVLESS))

        var unicodeSecret = base
        try mutateServer(&unicodeSecret) {
            $0["credential"] = ["kind": "keychain", "key": "server/credential-✅"]
        }
        invalidObjects.append(("non-ASCII secret key", unicodeSecret))

        var oversizedSecret = base
        try mutateServer(&oversizedSecret) {
            $0["credential"] = ["kind": "keychain", "key": String(repeating: "k", count: 513)]
        }
        invalidObjects.append(("oversized secret key", oversizedSecret))

        var unicodePath = base
        try mutateServer(&unicodePath) {
            $0["transport"] = ["kind": "ws", "options": ["path": "/✅"]]
        }
        invalidObjects.append(("non-ASCII transport path", unicodePath))

        var oversizedPath = base
        try mutateServer(&oversizedPath) {
            $0["transport"] = ["kind": "ws", "options": ["path": "/" + String(repeating: "a", count: 2048)]]
        }
        invalidObjects.append(("oversized transport path", oversizedPath))

        var missingServerName = base
        try mutateServer(&missingServerName) {
            var tls = $0["tls"] as? [String: Any] ?? [:]
            tls.removeValue(forKey: "serverName")
            $0["tls"] = tls
        }
        invalidObjects.append(("missing TLS server name", missingServerName))

        var unsafeALPN = base
        try mutateServer(&unsafeALPN) {
            var tls = $0["tls"] as? [String: Any] ?? [:]
            tls["alpn"] = ["unsafe value"]
            $0["tls"] = tls
        }
        invalidObjects.append(("unsafe ALPN", unsafeALPN))

        var trojanWithoutTLS = trojanBase
        try mutateServer(&trojanWithoutTLS) { $0["tls"] = NSNull() }
        invalidObjects.append(("trojan without TLS", trojanWithoutTLS))

        var shadowsocksWrongKind = shadowsocksBase
        try mutateServer(&shadowsocksWrongKind) {
            $0["transport"] = ["kind": "ws", "options": ["method": "aes-256-gcm"]]
        }
        invalidObjects.append(("shadowsocks wrong transport", shadowsocksWrongKind))

        var shadowsocksExtraOption = shadowsocksBase
        try mutateServer(&shadowsocksExtraOption) {
            $0["transport"] = [
                "kind": "tcp",
                "options": ["method": "aes-256-gcm", "host": "synthetic.example"]
            ]
        }
        invalidObjects.append(("shadowsocks extra option", shadowsocksExtraOption))

        var shadowsocksWithTLS = shadowsocksBase
        try mutateServer(&shadowsocksWithTLS) {
            $0["tls"] = [
                "serverName": "synthetic.example",
                "allowInsecure": false,
                "alpn": []
            ]
        }
        invalidObjects.append(("shadowsocks with TLS", shadowsocksWithTLS))

        var mismatchedDisplay = base
        mismatchedDisplay["displayValue"] = "vless://other.example:443/••••••••"
        invalidObjects.append(("display endpoint mismatch", mismatchedDisplay))

        for (index, testCase) in invalidObjects.enumerated() {
            let data = try JSONSerialization.data(withJSONObject: testCase.1)
            XCTAssertThrowsError(
                try JSONCoding.decoder().decode(ParsedShareLink.self, from: data),
                "case \(index)"
            ) { error in
                XCTAssertFalse(String(describing: error).contains("Canary"), "case \(index)")
            }
        }
    }

    func testDecodingRejectsMissingSecretReferenceAndUnsafeDisplayMetadata() throws {
        let parsed = try ShareLinkParser.parse(
            try fixtureData("trojan-share-link.txt"),
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/trojan/credential") },
            limits: ShareLinkLimits()
        )
        let encoded = try JSONCoding.encoder().encode(parsed)
        let validObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        var missingCredentialObject = validObject
        var missingCredentialServer = try XCTUnwrap(missingCredentialObject["server"] as? [String: Any])
        missingCredentialServer.removeValue(forKey: "credential")
        missingCredentialObject["server"] = missingCredentialServer
        var unsafeDisplayObject = validObject
        unsafeDisplayObject["displayValue"] = "trojan://synthetic.example:443/••••••••?Query-Canary"
        var unknownFieldObject = validObject
        unknownFieldObject["rawUrl"] = "trojan://Password-Canary@synthetic.example:443"
        var controlCharacterHostObject = validObject
        var controlCharacterServer = try XCTUnwrap(controlCharacterHostObject["server"] as? [String: Any])
        controlCharacterServer["endpoint"] = ["host": "synthetic.example\nQuery-Canary", "port": 443]
        controlCharacterHostObject["server"] = controlCharacterServer
        controlCharacterHostObject["displayValue"] = "redacted"
        let invalidObjects = [
            missingCredentialObject,
            unsafeDisplayObject,
            unknownFieldObject,
            controlCharacterHostObject
        ]

        for invalidObject in invalidObjects {
            let data = try JSONSerialization.data(withJSONObject: invalidObject)
            XCTAssertThrowsError(try JSONCoding.decoder().decode(ParsedShareLink.self, from: data)) { error in
                XCTAssertFalse(String(describing: error).contains("Canary"))
            }
        }
    }

    func testRejectsSecretReferenceContainingOneByteCredential() throws {
        let link = Data("trojan://z@synthetic.example:443?security=tls".utf8)
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                link,
                id: serverID,
                credentialSink: { _ in SecretReference(key: "server/z") },
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .invalidSecretReference)
        }

        let parsed = try ShareLinkParser.parse(
            link,
            id: serverID,
            credentialSink: { _ in SecretReference(key: "server/fixed") },
            limits: ShareLinkLimits()
        )
        XCTAssertEqual(parsed.secretReference, SecretReference(key: "server/fixed"))
    }

    func testEnforcesSecretReferenceByteBound() throws {
        let link = Data("trojan://Bound-Password-Canary@synthetic.example:443?security=tls".utf8)
        let maximumKey = String(repeating: "k", count: 512)
        let parsed = try ShareLinkParser.parse(
            link,
            id: serverID,
            credentialSink: { _ in SecretReference(key: maximumKey) },
            limits: ShareLinkLimits()
        )
        XCTAssertEqual(parsed.secretReference.key.utf8.count, 512)

        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                link,
                id: serverID,
                credentialSink: { _ in SecretReference(key: maximumKey + "k") },
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .invalidSecretReference)
        }
    }

    func testRejectsSecretReferenceThatEchoesTransientCredential() {
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("trojan://Trojan-Password-Canary@synthetic.example:443?security=tls".utf8),
                id: serverID,
                credentialSink: { _ in SecretReference(key: "server/Trojan-Password-Canary") },
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .invalidSecretReference)
            XCTAssertFalse(String(describing: error).contains("Canary"))
        }
    }

    func testCredentialSinkFailureIsReplacedWithTypedPrivacySafeError() {
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("trojan://Trojan-Password-Canary@synthetic.example:443?security=tls".utf8),
                id: serverID,
                credentialSink: { _ in throw CanarySinkError() },
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .credentialSinkFailed)
            XCTAssertFalse(String(describing: error).contains("Canary"))
            XCTAssertFalse(String(reflecting: error).contains("Canary"))
            XCTAssertFalse(error.localizedDescription.contains("Canary"))
        }
    }

    func testMutationSmokeCoversSchemeValidationIdentityAndExactSinkUse() throws {
        let vless = try fixtureData("vless-share-link.txt")
        let firstRecorder = CredentialRecorder()
        let first = try ShareLinkParser.parse(
            vless,
            id: serverID,
            credentialSink: firstRecorder.sink(referenceKey: "server/fixed"),
            limits: ShareLinkLimits()
        )
        let secondRecorder = CredentialRecorder()
        let second = try ShareLinkParser.parse(
            vless,
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000202")!,
            credentialSink: secondRecorder.sink(referenceKey: "server/fixed"),
            limits: ShareLinkLimits()
        )

        XCTAssertEqual(first.server.id, serverID)
        XCTAssertNotEqual(second.server.id, first.server.id)
        XCTAssertEqual(first.displayValue, second.displayValue)
        XCTAssertEqual(firstRecorder.values.count, 1)
        XCTAssertEqual(secondRecorder.values.count, 1)
        XCTAssertThrowsError(
            try ShareLinkParser.parse(
                Data("ssr://Credential-Canary".utf8),
                id: serverID,
                credentialSink: { _ in SecretReference(key: "server/unused") },
                limits: ShareLinkLimits()
            )
        ) { error in
            XCTAssertEqual(error as? ShareLinkParseError, .unsupportedScheme)
        }
    }

    private func jsonObject(_ parsed: ParsedShareLink) throws -> [String: Any] {
        let data = try JSONCoding.encoder().encode(parsed)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func mutateServer(
        _ object: inout [String: Any],
        mutation: (inout [String: Any]) -> Void
    ) throws {
        var server = try XCTUnwrap(object["server"] as? [String: Any])
        mutation(&server)
        object["server"] = server
    }

    private func fixtureData(_ name: String) throws -> Data {
        let url = repositoryRoot
            .appendingPathComponent("fixtures", isDirectory: true)
            .appendingPathComponent("subscriptions", isDirectory: true)
            .appendingPathComponent(name)
        return try Data(contentsOf: url)
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

private final class CredentialRecorder {
    private(set) var values: [Data] = []

    func sink(referenceKey: String = "server/test/credential") -> ShareLinkCredentialSink {
        { [self] value in
            values.append(value)
            return SecretReference(key: referenceKey)
        }
    }
}

private struct CanarySinkError: Error, LocalizedError {
    var errorDescription: String? { "Sink-Password-Canary" }
}
