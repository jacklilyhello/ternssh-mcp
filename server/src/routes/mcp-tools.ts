import type { Context } from "hono";
import { listMcpAuthorizedServers } from "../db/mcp-access";
import { prepareCommandBatch, readCommandBatch } from "../db/mcp-command-batches";
import { acceptSignedBatch, describeApproval } from "../db/mcp-batch-approvals";
import { callMcpBatch } from "../lib/mcp-batch-client";
import { ensureBatchExpiryAlarm } from "../do/mcp-batch-expiry";
import { checkTarget, OperationError, prepareTransfer, recordResult, reserveDiagnostic, resolveTarget } from "../db/mcp-operations";
import { isMcpDiagnostic, runMcpDiagnostic } from "../lib/mcp-ssh";
import { MCP_FILE_MAX_BYTES } from "../lib/mcp-files";
import { callMcpJob } from "../lib/mcp-job-client";
import { reserveWorkspaceRequest } from "../db/mcp-workspace-leases";
import { validateWorkspaceCommand } from "../lib/mcp-workspace";
import { JOB_DEFAULT_TIMEOUT_MS } from "../do/mcp-command-job";
import { MAX_JOB_PAGE_BYTES } from "../lib/mcp-job-output";
import { type McpEnvironment, unauthorized } from "./mcp-auth";

const serverId = { type: "string", minLength: 1, maxLength: 128 };
const uuidPattern = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
const uuidSchema = { type: "string", pattern: uuidPattern };
const shaPattern = "^[0-9a-f]{64}$";
const timeoutMs = { type: "integer", minimum: 1000, maximum: 600000 };
const pageLimit = { type: "integer", minimum: 1, maximum: MAX_JOB_PAGE_BYTES };
function tool(name: string, description: string, properties: object, required: string[], readOnly: boolean) {
  return { name, description, inputSchema: { type: "object", properties, required, additionalProperties: false },
    annotations: { readOnlyHint: readOnly, openWorldHint: name !== "list_authorized_servers" } };
}
export const catalog = [
  tool("list_authorized_servers", "List the servers selected and confirmed in the ternssh workspace.", {}, [], true),
  tool("run_workspace_command", "Run shell text on a selected server with workspaceShell enabled. Each job has a fresh isolated /work and no external network or host credentials. Save requestId before calling. Use the job tools for live output, tail, status and cancellation.",
    { serverId, requestId: uuidSchema, command: { type: "string", minLength: 1, maxLength: 4096 }, timeoutMs },
    ["serverId", "requestId", "command"], false),
  tool("prepare_command_batch", "Freeze one ordered batch for review on a selected server. This only creates a proposal; its ID and digest cannot authorize execution. A different command, order or timeout requires a new batch ID.",
    {serverId, batchId: uuidSchema, commands: {type: "array", minItems: 1, maxItems: 16,
      items: {type: "string", minLength: 1, maxLength: 4096}}, timeoutMs}, ["serverId", "batchId", "commands"], false),
  tool("get_command_batch", "Retrieve the immutable proposal, target, policy, expiry and digest for this pairing and current server grant.",
    {serverId, batchId: uuidSchema}, ["serverId", "batchId"], true),
  tool("approve_command_batch", "Submit the registered local approver's one-use signature over the complete batch. Only the local approver should call this. Query the batch ID if its reply is lost.",
    {serverId, batchId: uuidSchema, digest: {type:"string",pattern:shaPattern}, signature:{type:"string",minLength:88,maxLength:88}},
    ["serverId","batchId","digest","signature"], false),
  tool("get_command_batch_status", "Get batch state and per-command job IDs under the current grant. Use the job tools for output and tail.",
    {serverId, batchId: uuidSchema, digest:{type:"string",pattern:shaPattern}}, ["serverId","batchId","digest"], true),
  tool("cancel_command_batch", "Stop the approved batch and request cancellation of its current job.",
    {serverId, batchId: uuidSchema, digest:{type:"string",pattern:shaPattern}}, ["serverId","batchId","digest"], false),
  tool("run_diagnostic", "Run one fixed diagnostic on an authorized server. Set asJob=true for a resumable job whose ID is requestId. Keep the same ID to reconcile a lost job reply. Use fresh IDs for intentional new commands.",
    {serverId, diagnostic: {type: "string", enum: ["utc", "system_name", "check_exit"]}, requestId: uuidSchema, asJob: {type: "boolean"}, timeoutMs},
    ["serverId", "diagnostic", "requestId"], true),
  tool("read_job_output", "Read output in arrival order from a combined byte cursor, starting at zero. Resume at nextCursor. A running job may have no new bytes yet. Frames carry text and lossless base64.",
    {serverId, jobId: uuidSchema, cursor: {type: "integer", minimum: 0}, limit: pageLimit}, ["serverId", "jobId"], true),
  tool("read_job_tail", "Read the latest output in arrival order. Set stream to stdout or stderr for the latest bytes of that stream in streamTail.segments. Use nextCursor with read_job_output to follow new output from both streams.",
    {serverId, jobId: uuidSchema, limit: pageLimit, stream: {type: "string", enum: ["stdout", "stderr"]}}, ["serverId", "jobId"], true),
  tool("get_job_status", "Get the current state, exit status and output completeness of a job.",
    {serverId, jobId: uuidSchema}, ["serverId", "jobId"], true),
  tool("cancel_job", "Request termination of this job. Query its final state to determine whether the peer confirmed termination.",
    {serverId, jobId: uuidSchema}, ["serverId", "jobId"], false),
  tool("prepare_upload", "Prepare a one-use upload to the server's private transfer directory. Finish locally with scripts/mcp-transfer.mjs upload. To replace a managed file, pass its fileId as replaceFileId.",
    {serverId, bytes: {type: "integer", minimum: 0, maximum: MCP_FILE_MAX_BYTES}, sha256: {type: "string", pattern: shaPattern}, replaceFileId: uuidSchema},
    ["serverId", "bytes", "sha256"], false),
  tool("prepare_download", "Prepare a one-use download of a managed file from the authorized server. Finish locally with scripts/mcp-transfer.mjs download.",
    {serverId, fileId: uuidSchema}, ["serverId", "fileId"], true),
];

const uuid = new RegExp(uuidPattern);
const sha256 = new RegExp(shaPattern);
function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function only(args: Record<string, unknown>, keys: string[]) {
  return Object.keys(args).every(key => keys.includes(key));
}
function isUuid(value: unknown): value is string {
  return typeof value === "string" && uuid.test(value);
}
export async function callTool(c: Context<McpEnvironment>, id: string | number, name: unknown, args: unknown) {
  const invalid = (message: string) => c.json({ jsonrpc: "2.0", id, error: { code: -32602, message } });
  const output = (value: unknown, isError = false) => c.json({ jsonrpc: "2.0", id,
    result: { content: [{type: "text", text: JSON.stringify(value)}], ...(isError ? {isError: true} : {}) } });
  if (!catalog.some(entry => entry.name === name)) return invalid("Unknown tool");
  if (args === undefined) args = {};
  if (!object(args)) return invalid("Expected arguments object");
  const db = c.env.DB;
  try {
    if (name === "list_authorized_servers") {
      if (!only(args, [])) return invalid("This tool takes no arguments");
      const servers = await listMcpAuthorizedServers(db, c.get("token"));
      return servers ? output({servers}) : unauthorized();
    }
    const { serverId } = args;
    if (typeof serverId !== "string" || !serverId || serverId.length > 128) return invalid("Invalid serverId");
    const resolve = () => resolveTarget(db, c.get("digest"), serverId);
    if (name === "run_workspace_command") {
      const { requestId, command, timeoutMs: timeout = JOB_DEFAULT_TIMEOUT_MS } = args;
      if (!only(args, ["serverId", "requestId", "command", "timeoutMs"]) || !isUuid(requestId) ||
          typeof command !== "string" || typeof timeout !== "number" || !Number.isSafeInteger(timeout) ||
          timeout < timeoutMs.minimum || timeout > timeoutMs.maximum) {
        return invalid("Expected shell text, a UUIDv4 requestId and an optional per-job timeout");
      }
      const text = validateWorkspaceCommand(command);
      const target = await resolve();
      const action = await reserveWorkspaceRequest(db, target, requestId, timeout);
      const { result, failed } = await callMcpJob(c.env, target, requestId, { action, command: text, timeoutMs: timeout });
      if (action === "workspace-reconcile" && result.code === 404) {
        return output({ status: "unknown", jobId: requestId, error: "Request already reserved. Its dispatch cannot be confirmed." }, true);
      }
      return output(result, failed);
    }
    if (name === "prepare_command_batch" || name === "get_command_batch") {
      const { batchId, commands, timeoutMs: timeout } = args;
      if (!isUuid(batchId)) return invalid("Expected a UUIDv4 batch ID");
      if (name === "get_command_batch") {
        if (!only(args, ["serverId", "batchId"])) return invalid("Expected serverId and batchId");
        const target = await resolve();
        const proposal = await readCommandBatch(db, target, batchId);
        const described = await describeApproval(db, new URL(c.req.url).origin, target, proposal, c.env.TERNSSH_APPROVER_SHA256);
        await checkTarget(db, target);
        return output(described);
      }
      if (!only(args, ["serverId", "batchId", "commands", "timeoutMs"]) ||
          !Array.isArray(commands) || !commands.every((item): item is string => typeof item === "string") ||
          (timeout !== undefined && (typeof timeout !== "number" || !Number.isSafeInteger(timeout)))) {
        return invalid("Expected an ordered command array and optional integer timeoutMs");
      }
      const target = await resolve();
      await ensureBatchExpiryAlarm(c.env);
      const proposal = await prepareCommandBatch(db, target, { batchId, commands, timeoutMs: timeout });
      const described = await describeApproval(db, new URL(c.req.url).origin, target, proposal, c.env.TERNSSH_APPROVER_SHA256);
      await checkTarget(db, target);
      return output(described);
    }
    if (name === "approve_command_batch" || name === "get_command_batch_status" || name === "cancel_command_batch") {
      const submit = name === "approve_command_batch";
      const allowed = ["serverId", "batchId", "digest"];
      if (submit) allowed.push("signature");
      const { batchId, digest, signature } = args;
      if (!only(args, allowed) || !isUuid(batchId) || typeof digest !== "string" || !sha256.test(digest) ||
          (submit && (typeof signature !== "string" || signature.length !== 88))) return invalid("Invalid batch receipt");
      const target = await resolve();
      if (submit) {
        await acceptSignedBatch(db, new URL(c.req.url).origin, target, batchId, digest, signature as string, c.env.TERNSSH_APPROVER_SHA256);
      }
      const action = submit ? "start" : name === "cancel_command_batch" ? "cancel" : "status";
      const { result, failed } = await callMcpBatch(c.env, target, batchId, digest, action);
      await checkTarget(db, target);
      return output(result, failed);
    }
    if (name === "run_diagnostic") {
      if (!only(args, ["serverId","diagnostic","requestId","asJob","timeoutMs"]) || !isMcpDiagnostic(args.diagnostic) ||
        !isUuid(args.requestId)) return invalid("Expected a fixed diagnostic name and a UUIDv4 requestId");
      if (args.asJob !== undefined && typeof args.asJob !== "boolean") return invalid("Invalid asJob flag");
      if (args.timeoutMs !== undefined && (args.asJob !== true || typeof args.timeoutMs !== "number" ||
          !Number.isSafeInteger(args.timeoutMs) || args.timeoutMs < timeoutMs.minimum || args.timeoutMs > timeoutMs.maximum)) {
        return invalid("Invalid job timeout");
      }
      const target = await resolve();
      if (args.asJob === true) {
        // Share the receipt namespace with synchronous diagnostics. A retry whose first
        // reply was lost can inspect a job, but can never submit the SSH operation again.
        let action: "start" | "reconcile" = "start";
        try {
          await reserveDiagnostic(db, target, args.requestId);
        } catch (error) {
          if (!(error instanceof OperationError) || error.status !== 409) throw error;
          action = "reconcile";
        }
        const { result, failed } = await callMcpJob(c.env, target, args.requestId, {
          action, diagnostic: args.diagnostic, timeoutMs: args.timeoutMs ?? 120_000,
        });
        if (action === "reconcile" && result.code === 404) {
          return output({ status: "unknown", jobId: args.requestId, error: "Request ID already reserved. Its dispatch cannot be confirmed." }, true);
        }
        return output(result, failed);
      }
      await reserveDiagnostic(db, target, args.requestId);
      const result = await runMcpDiagnostic(db, target, args.diagnostic, () => checkTarget(db, target));
      await checkTarget(db, target);
      // A logging failure must not hide a command result that the server already received.
      await recordResult(db, target, result.status).catch(() => console.warn("MCP diagnostic audit unavailable"));
      return output(result, result.status !== "completed" || result.exitCode !== 0);
    }
    if (name === "get_job_status" || name === "cancel_job" || name === "read_job_output" || name === "read_job_tail") {
      const reading = name === "read_job_output" || name === "read_job_tail";
      const keys = ["serverId", "jobId"];
      if (reading) keys.push("limit");
      if (name === "read_job_output") keys.push("cursor");
      if (name === "read_job_tail") keys.push("stream");
      const { jobId, limit, cursor, stream } = args;
      if (!only(args, keys) || !isUuid(jobId) ||
          (limit !== undefined && (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_JOB_PAGE_BYTES)) ||
          (cursor !== undefined && (typeof cursor !== "number" || !Number.isSafeInteger(cursor) || cursor < 0)) ||
          (stream !== undefined && stream !== "stdout" && stream !== "stderr")) {
        return invalid("Invalid job ID, cursor, page limit or output stream");
      }
      const { result, failed } = await callMcpJob(c.env, await resolve(), jobId,
        name === "read_job_output" ? { action: "read", cursor, limit } :
        name === "read_job_tail" ? { action: "tail", limit, stream } :
        { action: name === "cancel_job" ? "cancel" : "status" });
      return output(result, failed);
    }
    if (name === "prepare_upload") {
      if (!only(args, ["serverId","bytes","sha256","replaceFileId"]) ||
          typeof args.bytes !== "number" || !Number.isSafeInteger(args.bytes) || args.bytes < 0 ||
          args.bytes > MCP_FILE_MAX_BYTES || typeof args.sha256 !== "string" || !sha256.test(args.sha256) ||
          (args.replaceFileId !== undefined && !isUuid(args.replaceFileId))) return invalid("Invalid upload description");
      return output(await prepareTransfer(db, await resolve(),
        {direction: "upload", bytes: args.bytes, sha256: args.sha256, replaceFileId: args.replaceFileId}));
    }
    if (!only(args, ["serverId","fileId"]) || !isUuid(args.fileId)) return invalid("Expected a managed fileId");
    return output(await prepareTransfer(db, await resolve(), {direction: "download", fileId: args.fileId}));
  } catch (error) {
    if (error instanceof OperationError) return output({status: "failed", error: error.message, code: error.status}, true);
    throw error;
  }
}
