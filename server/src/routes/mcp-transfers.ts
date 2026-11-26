import { Hono } from "hono";
import { checkTarget, checkTransfer, claimTransfer, OperationError, publishUpload, recordResult, releaseDownload, type AuditResult, type Transfer } from "../db/mcp-operations";
import { downloadMcpFile, MCP_FILE_MAX_BYTES, McpFileCommitUnknownError, removeMcpFile, uploadMcpFile, type McpFileSpec } from "../lib/mcp-files";
import { McpSshError, openPinnedMcpSession } from "../lib/mcp-ssh";
import type { SSHSession } from "../ssh/session";
import { type McpEnvironment, requireMcpToken } from "./mcp-auth";

export const mcpTransferRoutes = new Hono<McpEnvironment>();
mcpTransferRoutes.onError((_error, c) => c.json({ status: "failed", error: "Transfer service unavailable" }, 503, { "Cache-Control": "no-store" }));
mcpTransferRoutes.use("*", requireMcpToken);

const operationId = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
class PublicationUnknown extends Error {}

function fileSpec(file: {storageId: string; bytes: number; sha256: string}): McpFileSpec {
  return { fileId: file.storageId, size: file.bytes, sha256: file.sha256 };
}

function checkHeaders(request: Request, upload: boolean) {
  if (request.headers.has("Range") || (request.headers.get("Content-Encoding") ?? "identity").toLowerCase() !== "identity") {
    throw new OperationError("Partial or encoded transfers are unsupported", 415);
  }
  if (!upload) return;
  if (request.headers.get("Content-Type")?.toLowerCase() !== "application/octet-stream") {
    throw new OperationError("Expected application/octet-stream", 415);
  }
  const length = request.headers.get("Content-Length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MCP_FILE_MAX_BYTES)) {
    throw new OperationError("Invalid or oversized request body", 413);
  }
  if (!/^[0-9a-f]{64}$/.test(request.headers.get("X-Content-SHA256") ?? "")) {
    throw new OperationError("Expected SHA-256 metadata", 400);
  }
}

async function uploadBytes(request: Request, item: Transfer, signal: AbortSignal) {
  const length = request.headers.get("Content-Length");
  if ((length !== null && Number(length) !== item.bytes) || request.headers.get("X-Content-SHA256") !== item.sha256) {
    throw new OperationError("Body metadata differs from the prepared upload", 400);
  }
  const bytes = new Uint8Array(item.bytes);
  const reader = request.body?.getReader();
  let offset = 0;
  if (reader) {
    const cancel = () => { void reader.cancel().catch(() => {}); };
    signal.addEventListener("abort", cancel, { once: true });
    try {
      while (true) {
        signal.throwIfAborted();
        const chunk = await reader.read();
        if (chunk.done) break;
        if (chunk.value.length > bytes.length - offset) throw new OperationError("Body exceeds its prepared size", 413);
        bytes.set(chunk.value, offset);
        offset += chunk.value.length;
      }
    } catch (error) {
      cancel();
      throw error;
    } finally {
      signal.removeEventListener("abort", cancel);
      reader.releaseLock();
    }
  }
  signal.throwIfAborted();
  if (offset !== item.bytes) throw new OperationError("Incomplete upload", 400);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  if (Array.from(hash, byte => byte.toString(16).padStart(2, "0")).join("") !== item.sha256) {
    throw new OperationError("Body digest differs from the prepared upload", 400);
  }
  return bytes;
}

async function audit(db: D1Database, item: Transfer, result: AuditResult) {
  try { await recordResult(db, item, result); }
  catch { console.warn("MCP transfer audit unavailable"); }
}

mcpTransferRoutes.on(["GET", "PUT"], "/:id", async c => {
  const request = c.req.raw;
  if (request.method !== "GET" && request.method !== "PUT") return c.body(null, 405, { Allow: "GET, PUT" });
  if (!operationId.test(c.req.param("id"))) return c.json({ status: "failed", error: "Invalid transfer ID" }, 400);
  const upload = request.method === "PUT";
  const db = c.env.DB;
  let item: Transfer | undefined;
  let session: SSHSession | undefined;
  let signal: AbortSignal | undefined;
  let deadline: AbortSignal | undefined;
  const close = () => session?.close();
  try {
    checkHeaders(request, upload);
    item = await claimTransfer(db, c.get("digest"), c.req.param("id"), upload ? "upload" : "download");
    const ticket = item;
    // The local client waits for 60 s. Reserve time to return a definitive failure when possible.
    deadline = AbortSignal.timeout(Math.min(45_000, Math.max(1, ticket.expires * 1000 - Date.now())));
    const active = AbortSignal.any([request.signal, deadline]);
    signal = active;
    active.addEventListener("abort", close, { once: true });
    const authorize = async () => {
      active.throwIfAborted();
      await checkTransfer(db, ticket);
      active.throwIfAborted();
    };
    const authorizeCleanup = async () => {
      active.throwIfAborted();
      await checkTarget(db, ticket);
      active.throwIfAborted();
    };
    const bytes = upload ? await uploadBytes(request, ticket, active) : undefined;
    await authorize();
    session = await openPinnedMcpSession(db, ticket, authorize, active);
    active.throwIfAborted();
    const client = await session.openSftpClient();
    const spec = fileSpec(ticket);
    if (bytes === undefined) {
      const body = await downloadMcpFile(client, spec, authorize);
      active.throwIfAborted();
      // This audit records verified remote bytes. Only the local client can confirm file installation.
      await releaseDownload(db, ticket);
      return c.body(body, 200, { "Content-Type": "application/octet-stream", "Content-Length": String(body.length),
        "X-Content-SHA256": ticket.sha256, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store, no-transform" });
    }
    await uploadMcpFile(client, spec, bytes, authorize);
    active.throwIfAborted();
    try {
      await publishUpload(db, ticket);
    } catch (error) {
      // A D1 transport failure can arrive after commit. Deleting the object would corrupt a committed handle.
      if (!(error instanceof OperationError)) throw new PublicationUnknown();
      if (!active.aborted) {
        try { await removeMcpFile(client, spec, authorizeCleanup); } catch { /* an unpublished object is inaccessible */ }
      }
      throw error;
    }
    await audit(db, ticket, "uploaded");
    if (ticket.previous && !active.aborted) {
      try { await removeMcpFile(client, fileSpec(ticket.previous), authorizeCleanup); }
      catch { /* Logical replacement is committed even if retiring its private predecessor fails. */ }
    }
    return c.json({ status: "uploaded", fileId: ticket.fileId, bytes: ticket.bytes, sha256: ticket.sha256 });
  } catch (error) {
    const unknown = error instanceof McpFileCommitUnknownError || error instanceof PublicationUnknown;
    const timedOut = deadline?.aborted || (error instanceof McpSshError && error.timedOut);
    const outcome = unknown ? "unknown" : timedOut ? "timeout" : "failed";
    if (item) await audit(db, item, outcome);
    if (unknown) return c.json({ status: outcome, error: "Upload outcome unknown; check the prepared file ID" }, 502);
    if (timedOut) return c.json({ status: outcome, error: "Transfer timed out" }, 504);
    if (request.signal.aborted) return c.json({ status: outcome, error: "Transfer interrupted" }, 408);
    if (error instanceof OperationError) return c.json({ status: outcome, error: error.message }, error.status);
    if (error instanceof McpSshError) return c.json({ status: outcome, error: "Verified SSH session unavailable" }, 422);
    return c.json({ status: outcome, error: "Managed file transfer failed" }, 502);
  } finally {
    signal?.removeEventListener("abort", close);
    close();
  }
});

mcpTransferRoutes.all("/:id", c => c.body(null, 405, { Allow: "GET, PUT" }));
mcpTransferRoutes.all("*", c => c.body(null, 404));
