import { eraseApprovedCommands, hasApprovalReceipt, readApprovedBatch } from "../db/mcp-batch-approvals";
import { checkTarget, OperationError, type Target } from "../db/mcp-operations";
import { batchObjectName } from "../lib/mcp-batch-client";
import { JOB_RETENTION_MS } from "./mcp-command-job";

const key = "approved-batch-run";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const receiptDigest = /^[0-9a-f]{64}$/;
const pollMs = 3000;
type End = "completed" | "failed" | "unknown" | "cancelled" | "timeout" | "expired";
type BatchStatus = "running" | "cancelling" | End;
interface Item {
  jobId: string;
  status: "waiting" | "starting" | "queued" | "running" | "skipped" | End;
  exitCode?: number | null;
  signal?: string | null;
  reason?: string | null;
}
interface Batch {
  batchId: string;
  digest: string;
  target: Target;
  current: number;
  deadline: number;
  status: BatchStatus;
  items: Item[];
  expiresAt: number | null;
  erased: boolean;
}
type RequestBody = Pick<Batch, "target" | "batchId" | "digest"> & { index?: number; jobId?: string };
type ChildReply = { status?: Item["status"]; running?: boolean; exitCode?: number | null;
  signal?: string | null; reason?: string | null };

const live = (b: Batch) => b.status === "running" || b.status === "cancelling";
function sameGrant(a: Target, b: Target) {
  return a.userId === b.userId && a.tokenId === b.tokenId && a.serverId === b.serverId &&
    a.revision === b.revision && a.identityVersion === b.identityVersion;
}

export class McpBatchRunner {
  constructor(private readonly ctx: DurableObjectState, private readonly env: Env) {}

  private get() { return this.ctx.storage.kv.get<Batch>(key); }
  private save(batch: Batch) { this.ctx.storage.kv.put(key, batch); }
  private schedule(delay = 0) { return this.ctx.storage.setAlarm(Date.now() + delay); }

  private view(b: Batch) {
    return Response.json({ batchId: b.batchId, digest: b.digest, status: b.status, running: live(b),
      items: b.items.map((item, index) => ({ index, ...item })), expiresAt: b.expiresAt },
    { status: b.status === "expired" ? 410 : 200 });
  }

  private expire(b: Batch) {
    b.status = "expired";
    b.items = [];
    this.save(b);
  }

  async fetch(req: Request): Promise<Response> {
    const action = new URL(req.url).pathname;
    if (req.method !== "POST" || !["/start", "/status", "/cancel", "/position"].includes(action)) {
      return Response.json({ error: "Unknown batch operation" }, { status: 404 });
    }
    const args: RequestBody = await req.json();
    const { target, batchId, digest } = args;
    const keys = action === "/position" ? ["target", "batchId", "digest", "index", "jobId"] : ["target", "batchId", "digest"];
    if (!target || !uuid.test(batchId) || !receiptDigest.test(digest) || Object.keys(args).some(k => !keys.includes(k)) ||
        !this.ctx.id.equals(this.env.SSH_SESSION.idFromName(batchObjectName(target, batchId)))) {
      return Response.json({ error: "Invalid batch reference" }, { status: 400 });
    }
    try {
      if (action === "/position") {
        // Also serves as the running child's single periodic authorization
        // request, including current deployment pin, grant and approval expiry.
        await readApprovedBatch(this.env.DB, target, batchId, digest, this.env.TERNSSH_APPROVER_SHA256);
      } else {
        await checkTarget(this.env.DB, target);
      }
      let batch = this.get();
      if (!batch && action === "/start") {
        const approved = await readApprovedBatch(this.env.DB, target, batchId, digest, this.env.TERNSSH_APPROVER_SHA256);
        // Re-read after D1 yields. Concurrent starts share precisely one set of child IDs.
        batch = this.get();
        if (!batch) {
          batch = { batchId, digest, target, current: 0, deadline: approved.expiresAt, status: "running",
            items: approved.commands.map(() => ({ jobId: crypto.randomUUID(), status: "waiting" })),
            expiresAt: null, erased: false };
          this.save(batch);
          await this.schedule();
        }
      }
      if (!batch && (action === "/status" || action === "/cancel") &&
          await hasApprovalReceipt(this.env.DB, target, batchId, digest)) {
        // A start may still be in flight following the one-use D1 write.
        // Status never fills in a missing dispatch or infers a remote result.
        batch = this.get();
        if (!batch && action === "/status") {
          await checkTarget(this.env.DB, target);
          return Response.json({ batchId, digest, status: "unknown", running: null, items: [],
            reason: "coordinator_receipt_unavailable" });
        }
        if (!batch) {
          // Fence a delayed start with a terminal receipt for this same ID.
          batch = { batchId, digest, target, current: 0, deadline: 0, status: "unknown",
            items: [], expiresAt: null, erased: false };
          await this.finish(batch, "unknown");
        }
      }
      if (!batch || !sameGrant(target, batch.target) || batch.batchId !== batchId || batch.digest !== digest) {
        throw new OperationError("Batch unavailable", 404);
      }
      if (action === "/position") {
        const current = batch.items[batch.current];
        if (batch.status !== "running" || batch.deadline <= Date.now() || batch.current !== args.index ||
          !current || current.jobId !== args.jobId || !["starting", "queued", "running"].includes(current.status)) {
          throw new OperationError("Batch position unavailable");
        }
        return new Response(null, { status: 204 });
      }
      if (action === "/cancel" && live(batch)) {
        batch.status = "cancelling";
        this.save(batch);
        await this.schedule();
      }
      await checkTarget(this.env.DB, target);
      const current = this.get()!;
      if (current.status !== "expired" && current.expiresAt !== null && Date.now() >= current.expiresAt) this.expire(current);
      return this.view(current);
    } catch (error) {
      if (error instanceof OperationError) return Response.json({ error: error.message }, { status: error.status });
      throw error;
    }
  }

  private async finish(b: Batch, status: End) {
    b.status = status;
    for (const item of b.items) if (item.status === "waiting") item.status = "skipped";
    b.expiresAt = Date.now() + JOB_RETENTION_MS;
    this.save(b);
    // Persist terminal state before cleaning the approved command body in D1.
    await this.schedule();
    await this.clean(b);
  }

  private async clean(b: Batch) {
    if (!b.erased) {
      await eraseApprovedCommands(this.env.DB, b.target, b.batchId, b.digest);
      b.erased = true;
      this.save(b);
    }
    if (b.expiresAt !== null && b.expiresAt > Date.now()) await this.ctx.storage.setAlarm(b.expiresAt);
    else if (b.status !== "expired") this.expire(b);
  }

  private child(b: Batch, action: "batch-item" | "status" | "cancel") {
    const jobId = b.items[b.current].jobId;
    const namespace = this.env.SSH_SESSION;
    const stub = namespace.get(namespace.idFromName(`mcp-job:${b.target.tokenId}:${jobId}`));
    const ref = { batchId: b.batchId, digest: b.digest, index: b.current };
    return stub.fetch(`https://mcp-job.internal/${action}`, {
      method: "POST", body: JSON.stringify({ target: b.target, jobId, ...ref }),
    });
  }

  // Each alarm advances at most one step. Clients can disconnect, and the
  // whole batch need not fit within a single alarm invocation's lifetime.
  async alarm(): Promise<boolean> {
    let b = this.get();
    if (!b) return false;
    if (!live(b)) { await this.clean(b); return true; }
    let item = b.items[b.current];
    const position = b.current;
    let action: "batch-item" | "cancel" | "status";
    if (item.status === "waiting") {
      if (b.status === "cancelling") { await this.finish(b, "cancelled"); return true; }
      try { await readApprovedBatch(this.env.DB, b.target, b.batchId, b.digest, this.env.TERNSSH_APPROVER_SHA256); }
      catch (error) {
        if (!(error instanceof OperationError)) throw error;
        const current = this.get()!;
        if (live(current) && current.current === position && current.items[position].status === "waiting") {
          await this.finish(current, current.status === "cancelling" ? "cancelled" : "failed");
        }
        return true;
      }
      b = this.get()!;
      if (!live(b) || b.current !== position || b.items[position].status !== "waiting") return true;
      if (b.status === "cancelling") { await this.finish(b, "cancelled"); return true; }
      item = b.items[b.current];
      item.status = "starting";
      this.save(b);
      // After this fence, recovery only queries the original job.
      await this.ctx.storage.sync();
      action = "batch-item";
    } else {
      action = b.status === "cancelling" ? "cancel" : "status";
    }

    let reply: ChildReply | undefined;
    let code = 0;
    try {
      const response = await this.child(b, action);
      code = response.status;
      if (response.ok) reply = await response.json<ChildReply>();
    } catch { /* Lost reply. Reconcile this exact child on the next alarm. */ }

    b = this.get()!;
    if (!live(b) || position !== b.current) return true;
    item = b.items[position];
    if (!reply) {
      if ((code === 0 || code >= 500) && Date.now() <= b.deadline) {
        await this.schedule(pollMs);
        return true;
      }
      // Once reserved, even a missing child cannot be silently submitted again.
      item.status = "unknown";
      await this.finish(b, "unknown");
      return true;
    }
    if (reply.running && (reply.status === "queued" || reply.status === "running")) {
      item.status = reply.status;
      this.save(b);
      await this.schedule(pollMs);
      return true;
    }
    const end = reply.status;
    if (!end || end === "waiting" || end === "starting" || end === "queued" || end === "running" || end === "skipped") {
      item.status = "unknown";
      await this.finish(b, "unknown");
      return true;
    }
    Object.assign(item, { status: end, exitCode: reply.exitCode ?? null, signal: reply.signal ?? null, reason: reply.reason ?? null });
    if (b.status === "cancelling") { await this.finish(b, end === "unknown" ? "unknown" : "cancelled"); return true; }
    if (end !== "completed" || reply.exitCode !== 0) {
      await this.finish(b, end === "completed" || end === "expired" ? "unknown" : end);
    } else if (++b.current === b.items.length) {
      await this.finish(b, "completed");
    } else {
      this.save(b);
      await this.schedule();
    }
    return true;
  }
}
