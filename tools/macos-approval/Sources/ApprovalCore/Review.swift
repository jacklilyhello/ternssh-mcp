import CryptoKit
import Foundation

// Set this to the instance HTTPS origin before building the signed approval app.
public let trustedOrigin = "https://your-ternssh.example"
private let policy = "sequential_independent_stop_on_failure_or_unknown"

public enum ApprovalError: Error {
    case invalidProposal, invalidSignature, invalidArguments, untrustedBuild, keychain, unavailable
    case expired, cancelled, uncertain
}

private func equalBytes(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }

private func hex(_ data: some Sequence<UInt8>) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

// Encode exactly the string subset of JS JSON.stringify, including literal
// UTF-8 outside ASCII. Foundation may choose different, equivalent escapes.
private func quoted(_ s: String) -> String {
    var out = "\""
    for cp in s.unicodeScalars {
        switch cp.value {
        case 34: out += "\\\""
        case 92: out += "\\\\"
        case 8: out += "\\b"
        case 9: out += "\\t"
        case 10: out += "\\n"
        case 12: out += "\\f"
        case 13: out += "\\r"
        case 0..<32: out += String(format: "\\u%04x", cp.value)
        default: out.unicodeScalars.append(cp)
        }
    }
    return out + "\""
}

// Display unambiguous ASCII for all bytes, including newlines, non-breaking
// spaces, bidi controls, terminal escapes and literally typed backslashes.
public func displayBytes(_ s: String) -> String {
    s.utf8.map { byte in
        switch byte {
        case 10: return "\\n"
        case 9: return "\\t"
        case 13: return "\\r"
        case 92: return "\\\\"
        case 32...126: return String(UnicodeScalar(byte))
        default: return String(format: "\\x%02X", byte)
        }
    }.joined()
}

// Keep common left-to-right scripts readable. Escape direction controls,
// combining/variation marks, whitespace and scripts that can reorder shell
// punctuation. A second view always exposes every original UTF-8 byte.
public func displayText(_ s: String) -> String {
    var text = ""
    for cp in s.unicodeScalars {
        if cp.value <= 0x7f { text += displayBytes(String(cp)); continue }
        let visibleRange = (0x00c0...0x052f).contains(cp.value) ||
            (0x3001...0x30ff).contains(cp.value) || (0x3400...0x4dbf).contains(cp.value) ||
            (0x4e00...0x9fff).contains(cp.value) || (0xac00...0xd7a3).contains(cp.value) ||
            (0xff01...0xff60).contains(cp.value) || (0x20000...0x323af).contains(cp.value)
        switch cp.properties.generalCategory {
        case .lowercaseLetter, .uppercaseLetter, .titlecaseLetter, .otherLetter,
             .openPunctuation, .closePunctuation, .otherPunctuation, .decimalNumber:
            if visibleRange && !cp.properties.isDefaultIgnorableCodePoint {
                text.unicodeScalars.append(cp)
                continue
            }
        default: break
        }
        text += String(format: "\\u{%X}", cp.value)
    }
    return text
}

public struct Proposal: Decodable {
    let version: Int, status: String, policy: String
    let batchId: String, serverId: String, serverName: String, identityVersion: String
    let revision: Int, commands: [String], timeoutMs: Int, digest: String, expiresAt: Int64
    let approvalPayloadBase64: String
}

private struct Envelope: Decodable {
    let origin: String, user: String, token: String, server: String, name: String, identity: String
    let revision: Int, batch: String, timeout: Int, policyName: String, commands: [String]
    let digest: String, challenge: String, expiry: Int64

    init(from decoder: Decoder) throws {
        var c = try decoder.unkeyedContainer()
        guard try c.decode(String.self) == "ternssh/batch-approval", try c.decode(Int.self) == 1 else {
            throw ApprovalError.invalidProposal
        }
        origin = try c.decode(String.self); user = try c.decode(String.self); token = try c.decode(String.self)
        server = try c.decode(String.self); name = try c.decode(String.self); identity = try c.decode(String.self)
        revision = try c.decode(Int.self); batch = try c.decode(String.self); timeout = try c.decode(Int.self)
        policyName = try c.decode(String.self); commands = try c.decode([String].self)
        digest = try c.decode(String.self); challenge = try c.decode(String.self); expiry = try c.decode(Int64.self)
        guard c.isAtEnd else { throw ApprovalError.invalidProposal }
    }

    var proposalDigest: String {
        let cmd = "[" + commands.map(quoted).joined(separator: ",") + "]"
        let fields = [quoted("ternssh/mcp-command-batch"), "1", quoted(policyName), quoted(user),
                      quoted(token), quoted(server), String(revision), quoted(identity), quoted(name),
                      quoted(batch), String(timeout), cmd]
        return hex(SHA256.hash(data: Data(("[" + fields.joined(separator: ",") + "]").utf8)))
    }
}

public struct VerifiedBatch {
    public let signingBytes: Data, digest: String, review: String, byteReview: String, expiresAt: Int64
    public let tokenId: String

    public init(proposal: Proposal, server: String, batch: String, now: Date = Date()) throws {
        guard proposal.approvalPayloadBase64.utf8.count <= 64 * 1024,
              let data = Data(base64Encoded: proposal.approvalPayloadBase64),
              data.base64EncodedString() == proposal.approvalPayloadBase64 else { throw ApprovalError.invalidProposal }
        let e = try JSONDecoder().decode(Envelope.self, from: data)
        let milliseconds = Int64(now.timeIntervalSince1970 * 1000)
        guard e.expiry > milliseconds, e.expiry <= milliseconds + 901_000 else { throw ApprovalError.expired }
        let hex64 = try NSRegularExpression(pattern: "^[0-9a-f]{64}\\z")
        func matchesHex(_ s: String) -> Bool {
            hex64.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
        }
        guard UUID(uuidString: batch)?.uuidString.lowercased() == batch,
              proposal.status == "proposed", proposal.version == 1,
              equalBytes(e.origin, trustedOrigin), equalBytes(e.server, server), equalBytes(e.batch, batch),
              equalBytes(e.server, proposal.serverId), equalBytes(e.name, proposal.serverName),
              equalBytes(e.identity, proposal.identityVersion), equalBytes(e.batch, proposal.batchId),
              !e.user.isEmpty, !e.token.isEmpty, !e.identity.isEmpty, e.revision > 0,
              e.policyName == policy, proposal.policy == policy, e.revision == proposal.revision,
              e.timeout == proposal.timeoutMs, (1000...600000).contains(e.timeout),
              e.expiry == proposal.expiresAt, e.digest == proposal.digest, matchesHex(e.challenge),
              matchesHex(e.digest), e.proposalDigest == e.digest, (1...16).contains(e.commands.count),
              e.commands.count == proposal.commands.count,
              zip(e.commands, proposal.commands).allSatisfy({ equalBytes($0.0, $0.1) }),
              e.commands.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 && !$0.utf8.contains(0) }),
              e.commands.reduce(0, { $0 + $1.utf8.count }) <= 8192 else { throw ApprovalError.invalidProposal }
        signingBytes = data
        digest = e.digest
        tokenId = e.token
        expiresAt = e.expiry
        func lines(_ render: (String) -> String) -> [String] {
            e.commands.enumerated().map { "\($0.offset + 1). [\($0.element.utf8.count) bytes] \(render($0.element))" }
        }
        let expiry = ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: Double(e.expiry) / 1000))
        review = ([
            "Origin  \(trustedOrigin)", "Server  \(displayText(e.name))", "Server ID  \(displayText(e.server))",
            "Target identity  \(displayBytes(e.identity))", "Authorization revision  \(e.revision)",
            "Batch  \(e.batch)", "Expires  \(expiry)", "Timeout for each command  \(e.timeout) ms",
            "Each command runs once in order, in an independent SSH session. Stop on failure or unknown result.",
            "SHA-256  \(e.digest)", "",
            "Commands in execution order. Controls, invisible characters and backslashes are escaped.",
        ] + lines(displayText)).joined(separator: "\n")
        byteReview = (["Server  " + displayBytes(e.name), "Server ID  " + displayBytes(e.server), "",
                       "Non-ASCII and non-printing UTF-8 bytes are escaped. Literal backslashes are doubled."]
                      + lines(displayBytes)).joined(separator: "\n")
    }
}
