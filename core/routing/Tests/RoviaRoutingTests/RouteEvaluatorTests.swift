import XCTest
@testable import RoviaConfig
@testable import RoviaRouting

final class RouteEvaluatorTests: XCTestCase {
    func testNormalizesHostnameAndUsesFirstMatchingRule() throws {
        let streamingID = UUID(uuidString: "00000000-0000-0000-0000-000000000010")!
        let serverID = UUID(uuidString: "00000000-0000-0000-0000-000000000013")!
        let rules = [
            RouteRule(
                id: UUID(uuidString: "00000000-0000-0000-0000-000000000011")!,
                enabled: true,
                matchers: [.domainSuffix("youtube.com")],
                action: .group(streamingID)
            ),
            RouteRule(
                id: UUID(uuidString: "00000000-0000-0000-0000-000000000012")!,
                enabled: true,
                matchers: [.domain("blocked.example")],
                action: .block
            )
        ]

        let trace = try RouteEvaluator().evaluate(
            RouteInput(host: "WWW.YouTube.com.", ip: nil, port: 443, network: "TCP"),
            using: RouteSet(rules: rules, defaultAction: .direct),
            context: RouteEvaluationContext(
                knownGroupIDs: [streamingID],
                selectedServers: [streamingID: serverID]
            )
        )

        XCTAssertEqual(trace.normalizedInput.host, "www.youtube.com")
        XCTAssertEqual(trace.finalDecision, .group(streamingID))
        XCTAssertEqual(trace.selectedGroup, streamingID)
        XCTAssertEqual(trace.selectedServer, serverID)
        XCTAssertEqual(trace.evaluations.count, 2)
        XCTAssertTrue(trace.evaluations[0].matched)
        XCTAssertFalse(trace.evaluations[1].matched)
    }

    func testDomainSuffixDoesNotMatchUnrelatedSubstring() throws {
        let rule = RouteRule(
            id: UUID(),
            enabled: true,
            matchers: [.domainSuffix("youtube.com")],
            action: .block
        )

        let trace = try RouteEvaluator().evaluate(
            RouteInput(host: "notyoutube.com", ip: nil, port: 443, network: "tcp"),
            using: RouteSet(rules: [rule], defaultAction: .direct),
            context: RouteEvaluationContext()
        )

        XCTAssertEqual(trace.finalDecision, .direct)
        XCTAssertFalse(trace.evaluations[0].matched)
    }

    func testMatchesIPv4CIDRAndPort() throws {
        let rule = RouteRule(
            id: UUID(),
            enabled: true,
            matchers: [.ipCIDR("10.0.0.0/8"), .port(443)],
            action: .direct
        )

        let trace = try RouteEvaluator().evaluate(
            RouteInput(host: nil, ip: "10.12.0.9", port: 443, network: "tcp"),
            using: RouteSet(rules: [rule], defaultAction: .direct),
            context: RouteEvaluationContext()
        )

        XCTAssertEqual(trace.finalDecision, .direct)
        XCTAssertTrue(trace.evaluations[0].matched)
    }

    func testMatchesIPv6CIDR() throws {
        let rule = RouteRule(
            id: UUID(),
            enabled: true,
            matchers: [.ipCIDR("2001:db8::/32")],
            action: .block
        )

        let trace = try RouteEvaluator().evaluate(
            RouteInput(host: nil, ip: "2001:DB8::1", port: 443, network: "tcp"),
            using: RouteSet(rules: [rule], defaultAction: .direct),
            context: RouteEvaluationContext()
        )

        XCTAssertEqual(trace.finalDecision, .block)
    }

    func testDisabledRuleIsRecordedAndSkipped() throws {
        let rule = RouteRule(
            id: UUID(),
            enabled: false,
            matchers: [.domain("example.com")],
            action: .block
        )

        let trace = try RouteEvaluator().evaluate(
            RouteInput(host: "example.com", ip: nil, port: 80, network: "tcp"),
            using: RouteSet(rules: [rule], defaultAction: .direct),
            context: RouteEvaluationContext()
        )

        XCTAssertEqual(trace.finalDecision, .direct)
        XCTAssertFalse(trace.evaluations[0].matched)
        XCTAssertEqual(trace.evaluations[0].reason, "disabled")
    }

    func testUnknownGroupReturnsTypedError() {
        let groupID = UUID()
        let rule = RouteRule(
            id: UUID(),
            enabled: true,
            matchers: [.domain("example.com")],
            action: .group(groupID)
        )

        XCTAssertThrowsError(
            try RouteEvaluator().evaluate(
                RouteInput(host: "example.com", ip: nil, port: 443, network: "tcp"),
                using: RouteSet(rules: [rule], defaultAction: .direct),
                context: RouteEvaluationContext()
            )
        ) { error in
            XCTAssertEqual(error as? RouteEvaluationError, .unknownGroup)
        }
    }

    func testInvalidDomainMatcherReturnsTypedError() {
        let rule = RouteRule(
            id: UUID(),
            enabled: true,
            matchers: [.domain(" ")],
            action: .direct
        )

        XCTAssertThrowsError(
            try RouteEvaluator().evaluate(
                RouteInput(host: "example.com", ip: nil, port: 443, network: "tcp"),
                using: RouteSet(rules: [rule], defaultAction: .direct),
                context: RouteEvaluationContext()
            )
        ) { error in
            XCTAssertEqual(error as? RouteEvaluationError, .invalidMatcher)
        }
    }

    func testInvalidCIDRReturnsTypedError() {
        let rule = RouteRule(
            id: UUID(),
            enabled: true,
            matchers: [.ipCIDR("10.0.0.0/99")],
            action: .direct
        )

        XCTAssertThrowsError(
            try RouteEvaluator().evaluate(
                RouteInput(host: nil, ip: "10.0.0.1", port: 443, network: "tcp"),
                using: RouteSet(rules: [rule], defaultAction: .direct),
                context: RouteEvaluationContext()
            )
        ) { error in
            XCTAssertEqual(error as? RouteEvaluationError, .invalidCIDR)
        }
    }

    func testInvalidIPErrorDoesNotExposeRawInput() {
        let canary = "invalid-ip-canary"
        let rule = RouteRule(
            id: UUID(),
            enabled: true,
            matchers: [.port(443)],
            action: .direct
        )

        XCTAssertThrowsError(
            try RouteEvaluator().evaluate(
                RouteInput(host: nil, ip: canary, port: 443, network: "tcp"),
                using: RouteSet(rules: [rule], defaultAction: .direct),
                context: RouteEvaluationContext()
            )
        ) { error in
            XCTAssertEqual(error as? RouteEvaluationError, .invalidIPAddress)
            XCTAssertFalse(String(describing: error).contains(canary))
            XCTAssertFalse(String(reflecting: error).contains(canary))
            XCTAssertFalse(error.localizedDescription.contains(canary))
        }
    }

    func testInvalidCIDRErrorDoesNotExposeRawInput() {
        let canary = "198.51.100.0/99"
        XCTAssertThrowsError(try RouteMatcherValidation.validate(.ipCIDR(canary))) { error in
            XCTAssertEqual(error as? RouteEvaluationError, .invalidCIDR)
            XCTAssertFalse(String(describing: error).contains(canary))
            XCTAssertFalse(String(reflecting: error).contains(canary))
            XCTAssertFalse(error.localizedDescription.contains(canary))
        }
    }

    func testMatcherValidationIsExposedByRoviaRouting() {
        XCTAssertNoThrow(try RouteMatcherValidation.validate(.domainSuffix("example.com")))
        XCTAssertThrowsError(try RouteMatcherValidation.validate(.ipCIDR("10.0.0.0/99")))
    }

    func testMatcherValidationRejectsRepeatedDomainDots() {
        XCTAssertThrowsError(try RouteMatcherValidation.validate(.domain("example..")))
        XCTAssertThrowsError(try RouteMatcherValidation.validate(.domain("example..com")))
    }

    func testPortRangeReportsTheInvalidUpperBound() {
        XCTAssertThrowsError(try RouteMatcherValidation.validate(.portRange(lower: 80, upper: 70_000))) { error in
            XCTAssertEqual(error as? RouteEvaluationError, .invalidPort)
        }
    }

    func testPortRangeRejectsAnInvertedRangeAsAMatcherError() {
        XCTAssertThrowsError(try RouteMatcherValidation.validate(.portRange(lower: 443, upper: 80))) { error in
            XCTAssertEqual(error as? RouteEvaluationError, .invalidMatcher)
        }
    }

    // MARK: - The raw trace is an in-memory explanation

    func testTheRawTraceKeepsTheInputAndTheRedactedDiagnosticDoesNot() throws {
        // This is the reason the trace is not Codable. The two types answer the
        // same question and differ in exactly one way: the trace holds what the
        // user asked about, the diagnostic does not. If that ever stops being
        // true, the diagnostic can be persisted and the trace still cannot.
        let input = RouteInput(host: "Node.Example.Invalid", port: 443, network: "tcp")
        let routeSet = RouteSet(
            rules: [
                RouteRule(
                    id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
                    enabled: true,
                    matchers: [.domainSuffix("example.invalid")],
                    action: .block
                )
            ],
            defaultAction: .direct
        )

        let trace = try RouteEvaluator().evaluate(input, using: routeSet, context: RouteEvaluationContext())
        XCTAssertEqual(trace.input.host, "Node.Example.Invalid")
        XCTAssertEqual(trace.normalizedInput.host, "node.example.invalid")
        XCTAssertNotEqual(trace.input.host, trace.normalizedInput.host)

        let diagnostic = try RouteEvaluator().explain(input, using: routeSet)
        XCTAssertTrue(diagnostic.inputSummary.hasHost)
        XCTAssertFalse(diagnostic.inputSummary.hasIP)
        XCTAssertTrue(diagnostic.inputSummary.hasPort)
        XCTAssertTrue(diagnostic.inputSummary.hasNetwork)
        XCTAssertEqual(diagnostic.inputSummary.host, "redacted")
        XCTAssertNil(diagnostic.inputSummary.port)
        XCTAssertEqual(diagnostic.finalDecision, .block)

        // The diagnostic is the serializable one, and it is the one the control
        // schema describes.
        let encoded = try JSONEncoder().encode(diagnostic)
        let text = String(decoding: encoded, as: UTF8.self)
        XCTAssertTrue(text.contains("\"inputSummary\""))
        XCTAssertFalse(text.contains("Node.Example.Invalid"))
        XCTAssertFalse(text.contains("node.example.invalid"))
    }

    func testTheRedactedDiagnosticRoundTripsThroughItsContract() throws {
        let input = RouteInput(host: "node.example.invalid", port: 443)
        let diagnostic = try RouteEvaluator().explain(
            input,
            using: RouteSet(rules: [], defaultAction: .direct)
        )

        let decoded = try JSONDecoder().decode(RoutingDiagnostic.self, from: JSONEncoder().encode(diagnostic))

        XCTAssertEqual(decoded, diagnostic)
        XCTAssertEqual(decoded.reasonCode, "defaultAction")
    }
}

/// The evaluator normalises both sides of a domain comparison, and a degenerate
/// name normalises to nothing. `nil == nil` is true in Swift, so comparing the
/// two Optionals directly made a degenerate matcher match a degenerate host — a
/// rule that described nothing, matching an input that named nothing.
final class DegenerateHostTests: XCTestCase {
    private func evaluate(
        matcher: RouteMatcher,
        host: String?
    ) throws -> RouteAction {
        let rule = RouteRule(
            id: UUID(uuidString: "00000000-0000-0000-0000-0000000000a1")!,
            enabled: true,
            matchers: [matcher],
            action: .block
        )
        let input = RouteInput(host: host, ip: nil, port: nil, network: nil)
        return try RouteEvaluator().explain(
            input,
            using: RouteSet(rules: [rule], defaultAction: .direct)
        ).finalDecision
    }

    func test_a_degenerate_matcher_is_refused_before_it_can_match_anything() throws {
        // It used to normalise to "." and pass validation, and then the
        // comparison of two Optionals made nil == nil true, so it matched. It is
        // now refused up front, which is the better of the two answers: a rule
        // that names nothing is a configuration error, not a rule.
        for matcher in [".", "..", "...", ".example.com", "example..com"] {
            for host in [".", "..", "example.com"] {
                XCTAssertThrowsError(
                    try evaluate(matcher: .domain(matcher), host: host),
                    "the matcher " + matcher.debugDescription + " was accepted for the host "
                        + host.debugDescription
                ) { error in
                    guard case RouteEvaluationError.invalidMatcher = error else {
                        return XCTFail(
                            "expected invalidMatcher, got " + String(describing: error)
                        )
                    }
                }
            }
        }
    }

    func test_a_real_matcher_still_matches_its_host() throws {
        XCTAssertEqual(
            try evaluate(matcher: .domain("example.com"), host: "example.com"),
            .block
        )
        XCTAssertEqual(
            try evaluate(matcher: .domain("example.com."), host: "Example.com"),
            .block,
            "normalisation is still applied on both sides",
        )
    }

    func test_a_degenerate_host_falls_through_to_the_default() throws {
        XCTAssertEqual(try evaluate(matcher: .domain("example.com"), host: ".."), .direct)
    }

    func test_a_degenerate_suffix_matcher_is_refused_too() throws {
        // The suffix form validates through the same normaliser, so ".." is
        // refused there as well rather than becoming a suffix that matches
        // everything ending in a dot.
        XCTAssertThrowsError(try evaluate(matcher: .domainSuffix(".."), host: "example.com")) {
            guard case RouteEvaluationError.invalidMatcher = $0 else {
                return XCTFail("expected invalidMatcher, got " + String(describing: $0))
            }
        }
    }
}
