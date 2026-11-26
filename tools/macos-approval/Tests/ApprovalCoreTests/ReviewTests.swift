import CryptoKit
import Foundation
import XCTest
@testable import ApprovalCore

final class ReviewTests: XCTestCase {
    let batchID = "fe97d5ec-21e9-48e1-a364-a5c1e598dc53"
    let clock = Date(timeIntervalSince1970: 1000)
    let expiry = 1_100_000
    let policy = "sequential_independent_stop_on_failure_or_unknown"
    let commands = ["printf '%s' '香 港'", "first\nsecond\t\\n"]

    func bytes(_ object: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes])
    }

    func fixture(_ change: (inout [Any], inout [String: Any]) -> Void = { _, _ in }) throws -> Proposal {
        let list: [Any] = ["ternssh/mcp-command-batch", 1, policy, "user", "token", "server", 4, "identity",
                           "香港测试", batchID, 120000, commands]
        let digest = SHA256.hash(data: try bytes(list)).map { String(format: "%02x", $0) }.joined()
        var payload: [Any] = ["ternssh/batch-approval", 1, trustedOrigin, "user", "token", "server", "香港测试",
                              "identity", 4, batchID, 120000, policy, commands, digest, String(repeating: "f", count: 64), expiry]
        var proposal: [String: Any] = ["version": 1, "status": "proposed", "policy": policy, "batchId": batchID,
            "serverId": "server", "serverName": "香港测试", "identityVersion": "identity", "revision": 4,
            "commands": commands, "timeoutMs": 120000, "digest": digest, "expiresAt": expiry]
        change(&payload, &proposal)
        proposal["approvalPayloadBase64"] = try bytes(payload).base64EncodedString()
        return try JSONDecoder().decode(Proposal.self, from: bytes(proposal))
    }

    func validate(_ item: Proposal) throws -> VerifiedBatch {
        try VerifiedBatch(proposal: item, server: "server", batch: batchID, now: clock)
    }

    func testExactReviewBytes() throws {
        let result = try validate(fixture())
        XCTAssertTrue(result.review.contains("first\\nsecond\\t\\\\n"))
        XCTAssertTrue(result.review.contains("SHA-256  " + result.digest))
        XCTAssertTrue(result.review.contains("香港测试"))
        XCTAssertTrue(result.review.contains("香 港"))
        XCTAssertFalse(result.byteReview.contains("香港测试"))
        XCTAssertTrue(result.byteReview.contains(displayBytes("香港测试")))
        XCTAssertEqual(displayText("国\u{202e}\u{200b}\u{fe0f}\u{2028}e\u{301}\\n"),
                       "国\\u{202E}\\u{200B}\\u{FE0F}\\u{2028}e\\u{301}\\\\n")
        XCTAssertEqual(displayBytes("A \u{202e}\u{0}é\\n"), "A \\xE2\\x80\\xAE\\x00\\xC3\\xA9\\\\n")
        XCTAssertNotEqual(displayBytes("e\u{301}"), displayBytes("é"))
    }

    func testChangedBatchOrContextRejected() throws {
        for (slot, changed) in [(2, "https://other.invalid"), (3, "other owner"), (4, "other token"),
                                (5, "other host"), (6, "renamed host"), (7, "other identity"),
                                (9, UUID().uuidString.lowercased()), (11, "parallel"), (14, "bad challenge")] {
            let item = try fixture { envelope, _ in envelope[slot] = changed }
            XCTAssertThrowsError(try validate(item))
        }
        let mutations: [([Any]) -> [Any]] = [
            { old in var e = old; e[8] = 5; return e },
            { old in var e = old; e[10] = 121000; return e },
            { old in var e = old; e[12] = self.commands.reversed().map { $0 }; return e },
            { old in var e = old; e[15] = 0; return e },
            { $0 + ["extra"] },
        ]
        for mutation in mutations {
            let item = try fixture { e, _ in e = mutation(e) }
            XCTAssertThrowsError(try validate(item))
        }
        let substituted = try fixture { _, p in p["commands"] = ["different"] }
        XCTAssertThrowsError(try validate(substituted))
        XCTAssertThrowsError(try VerifiedBatch(proposal: fixture(), server: "other", batch: batchID, now: clock))
    }
}
