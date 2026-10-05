import Foundation
import XCTest
@testable import RoviaConfig

/// Direct coverage of `CanonicalRouteMatcherValidator`: every matcher kind's
/// refusal path, the CIDR parser's shape checks, and the IPv6 parser's
/// malformed-input edges.
final class RouteMatcherValidatorTests: XCTestCase {
    // MARK: - domain matchers

    func testDomainMatcherRejectsMalformedDomains() {
        let oversized = String(repeating: "a.", count: 127) + "a"
        XCTAssertGreaterThan(oversized.count, 253)

        for (label, value) in [
            ("degenerate", ".."),
            ("empty", ""),
            ("whitespace", "exa mple.com"),
            ("overlong name", oversized),
            ("overlong label", String(repeating: "a", count: 64) + ".com"),
            ("leading hyphen label", "-bad.example.com"),
            ("trailing hyphen label", "bad-.example.com"),
            ("non-ascii label", "exämple.com"),
        ] {
            XCTAssertThrowsError(
                try CanonicalRouteMatcherValidator.validate(.domain(value)),
                label
            ) { error in
                XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidMatcher("domain"), label)
            }
        }
    }

    func testDomainMatcherAcceptsNormalizedValidDomains() {
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate(.domain("example.com")))
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate(.domain("  Example.COM.  ")))
    }

    func testDomainSuffixMatcherValidatesLikeDomain() {
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.validate(.domainSuffix(".."))) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidMatcher("domainSuffix"))
        }
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate(.domainSuffix("example.com")))
    }

    // MARK: - port matchers

    func testPortMatcherRejectsOutOfRangePorts() {
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.validate(.port(0))) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidPort(0))
        }
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.validate(.port(65_536))) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidPort(65_536))
        }
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate(.port(1)))
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate(.port(65_535)))
    }

    func testPortRangeMatcherValidatesBoundsBeforeOrder() {
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.validate(.portRange(lower: 0, upper: 10))) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidPort(0))
        }
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.validate(.portRange(lower: 1, upper: 65_536))) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidPort(65_536))
        }
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.validate(.portRange(lower: 100, upper: 50))) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidMatcher("portRange"))
        }
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate(.portRange(lower: 80, upper: 443)))
    }

    // MARK: - network matchers

    func testNetworkMatcherRejectsEmptyAndControlCharacterValues() {
        for (label, value) in [
            ("empty", ""),
            ("whitespace only", "   "),
            ("control character", "tcp\u{7}"),
        ] {
            XCTAssertThrowsError(
                try CanonicalRouteMatcherValidator.validate(.network(value)),
                label
            ) { error in
                XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidMatcher("network"), label)
            }
        }
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate(.network("tcp")))
    }

    // MARK: - CIDR matchers

    func testIPCIDRMatcherRequiresAParseableCIDR() {
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.validate(.ipCIDR("not-a-cidr"))) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidCIDR("not-a-cidr"))
        }
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.validate(.ipCIDR("10.0.0.0/33"))) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidCIDR("10.0.0.0/33"))
        }
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate(.ipCIDR("10.0.0.0/8")))
    }

    func testParseCIDRRequiresASlashedNumericPrefix() throws {
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.parseCIDR("10.0.0.0")) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidCIDR("10.0.0.0"))
        }
        XCTAssertThrowsError(try CanonicalRouteMatcherValidator.parseCIDR("10.0.0.0/abc")) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidCIDR("10.0.0.0/abc"))
        }

        let v6 = try CanonicalRouteMatcherValidator.parseCIDR("::/0")
        XCTAssertEqual(v6.address.count, 16)
        XCTAssertEqual(v6.prefix, 0)
    }

    func testCIDRContainsReturnsFalseForAnUnparseableCandidate() throws {
        XCTAssertFalse(try CanonicalRouteMatcherValidator.cidr("10.0.0.0/8", contains: "not-an-address"))
    }

    func testCIDRContainsHandlesNonOctetAlignedPrefixes() throws {
        XCTAssertTrue(try CanonicalRouteMatcherValidator.cidr("10.0.0.0/9", contains: "10.127.0.1"))
        XCTAssertFalse(try CanonicalRouteMatcherValidator.cidr("10.0.0.0/9", contains: "10.128.0.1"))

        XCTAssertTrue(try CanonicalRouteMatcherValidator.cidr("2001:db8::/33", contains: "2001:db8:7fff::1"))
        XCTAssertFalse(try CanonicalRouteMatcherValidator.cidr("2001:db8::/33", contains: "2001:db8:8000::1"))
    }

    // MARK: - array validation

    func testMatcherArrayValidationStopsAtTheFirstInvalidMatcher() {
        XCTAssertThrowsError(
            try CanonicalRouteMatcherValidator.validate([.domain("valid.example"), .port(0)])
        ) { error in
            XCTAssertEqual(error as? CanonicalRouteValidationError, .invalidPort(0))
        }
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate([]))
        XCTAssertNoThrow(try CanonicalRouteMatcherValidator.validate([.network("tcp"), .port(443)]))
    }

    // MARK: - IPv6 parsing edges

    func testParseIPAddressRejectsMalformedIPv6Forms() {
        for (label, value) in [
            ("zone identifier", "fe80::1%en0"),
            ("double compression", "1::2::3"),
            ("too many groups before compression", "1:2:3:4:5:6:7:8::9"),
            ("too many hextets", "1:2:3:4:5:6:7:8:9"),
            ("overlong hextet", "2001:db8::12345"),
            ("non-hex hextet", "2001:db8::gggg"),
            ("empty hextet", "2001:db8:::1"),
        ] {
            XCTAssertNil(CanonicalRouteMatcherValidator.parseIPAddress(value), "\(label) was accepted")
        }
    }

    func testParseIPAddressAcceptsTheFullFormIPv6Address() {
        XCTAssertEqual(
            CanonicalRouteMatcherValidator.parseIPAddress("2001:0db8:0000:0000:0000:0000:0000:0001")?.count,
            16
        )
        XCTAssertEqual(
            CanonicalRouteMatcherValidator.normalizeIPAddress("2001:0DB8:0000:0000:0000:0000:0000:0001"),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        )
    }
}
