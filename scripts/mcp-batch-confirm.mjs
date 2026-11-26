import { execFile } from "node:child_process";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const helper = "/Applications/TernSSHApproval.app/Contents/MacOS/TernSSHApproval";
const versions = ["2025-11-25", "2025-06-18", "2025-03-26"];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const toolName = "confirm_command_batch";
const tool = {
  name: toolName,
  description: "Open the installed local approver to review one frozen ternssh batch. The user sees the target and exact commands and authorizes the signature locally. Use remote job tools for subsequent reads.",
  inputSchema: { type: "object", additionalProperties: false, required: ["serverId", "batchId"],
    properties: { serverId: { type: "string", minLength: 1, maxLength: 128 },
      batchId: { type: "string", pattern: uuid.source } } },
  annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
};

async function present(serverId, batchId) {
  // Do not pass bearer tokens, loader overrides, arbitrary argv or a signer path.
  const env = Object.fromEntries(["HOME", "TMPDIR", "LANG"].flatMap(key => process.env[key] ? [[key, process.env[key]]] : []));
  const { stdout } = await execFileAsync(helper, ["review", serverId, batchId], {
    env, timeout: 5 * 60_000, maxBuffer: 16384, cwd: "/",
  });
  const parsed = JSON.parse(stdout);
  if (parsed.serverId !== serverId || parsed.batchId !== batchId ||
      !["approved", "declined", "cancelled", "unknown", "failed"].includes(parsed.status)) throw new Error("Invalid local receipt");
  return { status: parsed.status, serverId, batchId };
}

export function approvalBridge() {
  let busy = false;
  return async message => {
    const { id, method, params } = message ?? {};
    const error = (code, reason) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message: reason } });
    const ok = result => ({ jsonrpc: "2.0", id, result });
    if (message?.jsonrpc !== "2.0" || typeof method !== "string") return error(-32600, "Invalid request");
    if (id === undefined && method.startsWith("notifications/")) return null;
    if (typeof id !== "string" && typeof id !== "number") return error(-32600, "Expected request ID");
    if (method === "initialize") return ok({
      protocolVersion: versions.includes(params?.protocolVersion) ? params.protocolVersion : versions[0],
      capabilities: { tools: {} }, serverInfo: { name: "ternssh-local-approval", version: "1.0.0" },
    });
    if (method === "ping") return ok({});
    if (method === "tools/list") return ok({ tools: [tool] });
    if (method !== "tools/call") return error(-32601, "Unknown method");
    const args = params?.arguments;
    if (params?.name !== toolName || !args || typeof args.serverId !== "string" ||
        !args.serverId || args.serverId.length > 128 || /[\u0000-\u001f\u007f]/u.test(args.serverId) ||
        typeof args.batchId !== "string" || !uuid.test(args.batchId) ||
        Object.keys(args).some(k => !["batchId", "serverId"].includes(k))) return error(-32602, "Invalid approval request");
    if (busy) return error(-32000, "Another local approval is in progress");
    busy = true;
    try {
      const receipt = await present(args.serverId, args.batchId);
      return ok({ content: [{ type:"text", text:JSON.stringify(receipt) }], isError: receipt.status !== "approved" });
    } catch {
      // A killed UI or a broken reply cannot establish whether the signed POST arrived.
      return ok({ content: [{ type:"text", text:JSON.stringify({ status:"unknown", batchId:args.batchId,
        error:"Local approval unavailable or reply lost. Check the existing batch ID." }) }], isError: true });
    } finally {
      busy = false;
    }
  };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const handle = approvalBridge();
  for await (const line of createInterface({ input:process.stdin, crlfDelay:Infinity, terminal:false })) {
    let reply;
    try {
      if (Buffer.byteLength(line) > 16384) throw new Error();
      reply = await handle(JSON.parse(line));
    } catch {
      reply = { jsonrpc:"2.0", id:null, error:{ code:-32700, message:"Invalid request" } };
    }
    if (reply) process.stdout.write(JSON.stringify(reply) + "\n");
  }
}
