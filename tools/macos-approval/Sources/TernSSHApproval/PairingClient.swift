import ApprovalCore
import Foundation

private final class RefuseRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

final class PairingClient {
    private let bearer: String
    private let session: URLSession
    private var sessionID: String?
    private var nextID = 1
    private let endpoint = URL(string: trustedOrigin + "/mcp")!

    init(bearer: String) {
        self.bearer = bearer
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.urlCache = nil
        config.timeoutIntervalForRequest = 20
        session = URLSession(configuration: config, delegate: RefuseRedirects(), delegateQueue: nil)
    }

    func close() { session.invalidateAndCancel() }

    private func post(_ message: [String: Any]) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("Bearer " + bearer, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json, text/event-stream", forHTTPHeaderField: "Accept")
        request.setValue("2025-11-25", forHTTPHeaderField: "MCP-Protocol-Version")
        if let sessionID { request.setValue(sessionID, forHTTPHeaderField: "Mcp-Session-Id") }
        request.httpBody = try JSONSerialization.data(withJSONObject: message)
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.url == endpoint, (200..<300).contains(http.statusCode) else {
            throw ApprovalError.unavailable
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < 160 * 1024 else { throw ApprovalError.invalidProposal }
            data.append(byte)
        }
        return (data, http)
    }

    private func rpc(_ method: String, _ params: [String: Any]) async throws -> [String: Any] {
        let id = nextID
        nextID += 1
        let (data, http) = try await post(["jsonrpc": "2.0", "id": id, "method": method, "params": params])
        guard http.mimeType == "application/json",
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["jsonrpc"] as? String == "2.0", object["id"] as? Int == id,
              object["error"] == nil, let result = object["result"] as? [String: Any] else {
            throw ApprovalError.unavailable
        }
        if method == "initialize" {
            sessionID = http.value(forHTTPHeaderField: "Mcp-Session-Id")
            guard result["protocolVersion"] as? String == "2025-11-25" else { throw ApprovalError.unavailable }
        }
        return result
    }

    func initialize() async throws {
        _ = try await rpc("initialize", ["protocolVersion": "2025-11-25", "capabilities": [:],
                                         "clientInfo": ["name": "ternssh-command-approval", "version": "1"]])
        let (_, response) = try await post(["jsonrpc": "2.0", "method": "notifications/initialized"])
        guard response.statusCode == 202 else { throw ApprovalError.unavailable }
    }

    private func toolResult(_ name: String, args: [String: String]) async throws -> Data {
        let result = try await rpc("tools/call", ["name": name, "arguments": args])
        guard result["isError"] as? Bool != true, let content = result["content"] as? [[String: Any]], content.count == 1,
              content[0]["type"] as? String == "text", let text = content[0]["text"] as? String else {
            throw ApprovalError.unavailable
        }
        return Data(text.utf8)
    }

    func getBatch(server: String, batch: String) async throws -> VerifiedBatch {
        let reply = try await toolResult("get_command_batch", args: ["serverId": server, "batchId": batch])
        let proposal = try JSONDecoder().decode(Proposal.self, from: reply)
        return try VerifiedBatch(proposal: proposal, server: server, batch: batch)
    }

    func approve(server: String, batch: String, reviewed: VerifiedBatch, signature: Data) async throws {
        do {
            let reply = try await toolResult("approve_command_batch", args: [
                "serverId": server, "batchId": batch, "digest": reviewed.digest,
                "signature": signature.base64EncodedString(),
            ])
            guard let object = try JSONSerialization.jsonObject(with: reply) as? [String: Any],
                  object["batchId"] as? String == batch,
                  let status = object["status"] as? String, ["approved", "queued", "running", "completed"].contains(status)
            else { throw ApprovalError.uncertain }
        } catch {
            // A timeout or lost receipt must never cause automatic re-submission.
            throw ApprovalError.uncertain
        }
    }
}
