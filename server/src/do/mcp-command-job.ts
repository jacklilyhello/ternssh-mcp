import { checkTarget, OperationError, recordResult, type Target } from "../db/mcp-operations";
import { checkWorkspaceGrant, digestToken } from "../db/mcp-access";
import { checkWorkspaceLease, releaseWorkspaceLease } from "../db/mcp-workspace-leases";
import { readApprovedBatch } from "../db/mcp-batch-approvals";
import { checkBatchPosition, type BatchItemRef } from "../lib/mcp-batch-client";
import { McpJobOutput, type JobStream } from "../lib/mcp-job-output";
import { validateWorkspaceCommand, workspaceShellCommand } from "../lib/mcp-workspace";
import { fixedDiagnosticCommand, isMcpDiagnostic, McpSshError, openPinnedMcpSession, type McpDiagnostic } from "../lib/mcp-ssh";
import { ExecCompletionError, type SSHSession } from "../ssh/session";

export const JOB_RETENTION_MS = 60 * 60 * 1000;
export const JOB_MAX_TIMEOUT_MS = 10 * 60 * 1000;
export const JOB_DEFAULT_TIMEOUT_MS = 120_000;
const metadataKey = "mcp-command-job";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
type JobStatus = "queued" | "running" | "completed" | "failed" | "unknown" | "cancelled" | "timeout" | "expired";
type StopReason = "cancelled" | "timeout" | "authorization_changed";
type Reason = StopReason | "connection_lost" | "no_exit_status" | "could_not_start" | "executor_restarted";

interface Job {
  id: string;
  target: Target;
  diagnostic?: McpDiagnostic;
  batch?: BatchItemRef;
  workspace?: { digest: string; command?: string };
  timeoutMs: number;
  deadline: number;
  expiresAt: number | null;
  status: JobStatus;
  dispatched: boolean;
  reason: Reason | null;
  exitCode: number | null;
  signal: string | null;
  outputEnded: boolean;
  auditClaimed?: boolean;
  expiredBytes?: number;
}

interface JobRequest {
  jobId: string;
  target: Target;
  diagnostic?: McpDiagnostic;
  command?: string;
  timeoutMs?: number;
  cursor?: number;
  limit?: number;
  stream?: JobStream;
  batchId?: string;
  digest?: string;
  index?: number;
}

function active(job: Job) {
  return job.status === "queued" || job.status === "running";
}

function sameTarget(a: Target, b: Target) {
  return a.tokenId === b.tokenId && a.serverId === b.serverId && a.userId === b.userId &&
    a.revision === b.revision && a.identityVersion === b.identityVersion;
}

// Every job has a separate name in the existing SQLite-backed SshSession namespace.
// Signed items resolve their text from an immutable D1 approval. A workspace
// job stores its input until terminal and only dispatches the bounded launcher.
export class McpCommandJob {
  private execution?: AbortController;
  private readonly storage: DurableObjectStorage;
  private log?: McpJobOutput;

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
    private readonly connect = openPinnedMcpSession,
  ) { this.storage = ctx.storage; }

  private output() { return this.log ??= new McpJobOutput(this.storage); }
  private readJob() { return this.storage.kv.get<Job>(metadataKey); }
  private save(job: Job) { this.storage.kv.put(metadataKey, job); }

  private async finish(job: Job, status: JobStatus, reason: Reason | null, ended: boolean) {
    const writeAudit = !job.auditClaimed;
    job.status = status;
    job.reason = reason;
    job.outputEnded = ended;
    job.expiresAt = Date.now() + JOB_RETENTION_MS;
    if (job.workspace) delete job.workspace.command;
    // Claim the best-effort metadata-only audit before the external write. A lost
    // acknowledgement must neither duplicate the entry nor change the SSH result.
    job.auditClaimed = true;
    this.save(job);
    await this.storage.setAlarm(job.expiresAt);
    if (job.workspace && (!job.dispatched || (status !== "unknown" && (job.exitCode !== null || job.signal !== null)))) {
      await releaseWorkspaceLease(this.env.DB, job.target, job.id).catch(() => {});
    }
    if (writeAudit) {
      const outcome = status === "completed" || status === "timeout" || status === "unknown" ? status : "failed";
      await recordResult(this.env.DB, job.target, outcome).catch(() => console.warn("MCP diagnostic audit unavailable"));
    }
  }

  private expire(job: Job) {
    const log = this.output();
    const bytes = log.summary().observedBytes;
    this.storage.transactionSync(() => {
      log.clear();
      // Keep a receipt so a delayed duplicate can never re-run this command.
      this.save({ ...job, status: "expired", expiredBytes: bytes });
    });
  }

  private response(job: Job, action: string, args: JobRequest) {
    const execution = job.workspace ? { environment: "isolated_workspace" } : {};
    if (job.status === "expired") {
      const end = job.expiredBytes ?? 0;
      return Response.json({ ...execution, jobId: job.id, status: "expired", running: false, expiresAt: job.expiresAt,
        outputState: "expired", observedBytes: end, missingRanges: end ? [{ start: 0, end }] : [],
        unknownSuffixFrom: !job.outputEnded && job.dispatched ? end : null }, { status: 410 });
    }
    const log = this.output();
    const result = action === "/read" ? log.read(args.cursor, args.limit) :
      action === "/tail" ? log.tail(args.limit, args.stream) : log.summary();
    const running = active(job);
    const unknownSuffix = !running && !job.outputEnded && job.dispatched;
    return Response.json({ ...result, ...execution, jobId: job.id, status: job.status, running, reason: job.reason,
      exitCode: job.exitCode, signal: job.signal, dispatched: job.dispatched,
      resultKnown: job.exitCode !== null || job.signal !== null,
      outputState: running ? "growing" : unknownSuffix || result.missingRanges.length ? "incomplete" : "complete",
      unknownSuffixFrom: unknownSuffix ? result.observedBytes : null, expiresAt: job.expiresAt });
  }

  async fetch(request: Request): Promise<Response> {
    const action = new URL(request.url).pathname;
    if (request.method !== "POST" || !["/start", "/workspace-start", "/workspace-reconcile",
      "/batch-item", "/reconcile", "/status", "/cancel", "/read", "/tail"].includes(action)) {
      return new Response(null, { status: 404 });
    }
    const args: JobRequest = await request.json();
    const target = args.target;
    if (!target || !uuid.test(args.jobId) || !this.ctx.id.equals(
      this.env.SSH_SESSION.idFromName(`mcp-job:${target.tokenId}:${args.jobId}`),
    )) return new Response(null, { status: 404 });
    try {
      await checkTarget(this.env.DB, target);
      if (args.stream !== undefined && (action !== "/tail" || (args.stream !== "stdout" && args.stream !== "stderr"))) {
        throw new OperationError("Invalid output stream", 400);
      }
      let timeout = args.timeoutMs ?? JOB_DEFAULT_TIMEOUT_MS;
      let ref: BatchItemRef | undefined;
      const submission = action === "/start" || action === "/reconcile";
      const workspaceSubmission = action === "/workspace-start" || action === "/workspace-reconcile";
      let workspace: Job["workspace"];
      if (submission || workspaceSubmission) {
        const allowed = ["target", "jobId", "timeoutMs", workspaceSubmission ? "command" : "diagnostic"];
        if (Object.keys(args).some(key => !allowed.includes(key)) || !Number.isSafeInteger(timeout) ||
          timeout < 1000 || timeout > JOB_MAX_TIMEOUT_MS) {
          throw new OperationError("Invalid job arguments or timeout", 400);
        }
        if (workspaceSubmission) {
          await checkWorkspaceGrant(this.env.DB, target);
          const command = validateWorkspaceCommand(args.command);
          const digest = await digestToken(JSON.stringify(["ternssh/workspace-job/v1", target.userId, target.tokenId,
            target.serverId, target.identityVersion, target.revision, args.jobId, timeout, command]));
          workspace = { digest, command };
        } else if (!isMcpDiagnostic(args.diagnostic)) {
          throw new OperationError("Invalid diagnostic", 400);
        }
      }
      if (action === "/batch-item") {
        if (typeof args.batchId !== "string" || !uuid.test(args.batchId) || typeof args.digest !== "string" ||
          !/^[0-9a-f]{64}$/.test(args.digest) || typeof args.index !== "number" || !Number.isInteger(args.index) ||
          args.index < 0 || Object.keys(args).some(k => !["target", "jobId", "batchId", "digest", "index"].includes(k))) {
          throw new OperationError("Invalid approved item reference", 400);
        }
        ref = { batchId: args.batchId, digest: args.digest, index: args.index };
        await checkBatchPosition(this.env, target, args.jobId, ref);
        const approved = await readApprovedBatch(this.env.DB, target, ref.batchId, ref.digest, this.env.TERNSSH_APPROVER_SHA256);
        if (ref.index >= approved.commands.length) throw new OperationError("Approved item unavailable", 404);
        timeout = approved.timeoutMs;
      }
      if (action === "/workspace-start" && !this.readJob()) {
        await checkWorkspaceLease(this.env.DB, target, args.jobId, timeout);
      }
      // Re-read after every external authorization/lease lookup. No two
      // concurrent submissions can both create the durable job and alarm.
      let job = this.readJob();
      if (!job) {
        if (!ref && action !== "/workspace-start" && action !== "/start") throw new OperationError("Job unavailable", 404);
        const source = workspace ? { workspace } : ref ? { batch: ref } : { diagnostic: args.diagnostic };
        job = { id: args.jobId, target, ...source,
          timeoutMs: timeout, deadline: Date.now() + timeout,
          expiresAt: null, status: "queued", dispatched: false, reason: null, exitCode: null, signal: null,
          outputEnded: false };
        this.save(job);
        // The alarm, not the client request, owns the socket and its full lifetime.
        await this.storage.setAlarm(Date.now());
      }
      if (job.id !== args.jobId || !sameTarget(job.target, target)) throw new OperationError("Job unavailable", 404);
      if (job.workspace) await checkWorkspaceGrant(this.env.DB, target);
      if (workspace && workspace.digest !== job.workspace?.digest) throw new OperationError("Request ID already used for another submission", 409);
      if ((action === "/status" || action === "/cancel") && args.batchId !== undefined &&
          (!job.batch || job.batch.batchId !== args.batchId || job.batch.digest !== args.digest || job.batch.index !== args.index)) {
        throw new OperationError("Approved item unavailable", 404);
      }
      if (ref && (ref.batchId !== job.batch?.batchId || ref.digest !== job.batch?.digest || ref.index !== job.batch?.index)) {
        throw new OperationError("Job already reserved", 409);
      }
      if (submission && (args.diagnostic !== job.diagnostic || timeout !== job.timeoutMs)) {
        throw new OperationError("Request ID already used for another submission", 409);
      }
      await this.recoverOrExpire(this.readJob()!);
      job = this.readJob()!;
      if (action === "/cancel" && active(job)) {
        if (this.execution) {
          if (!job.reason) {
            job.reason = "cancelled";
            this.save(job);
          }
          this.execution.abort();
        } else {
          await this.finish(job, "cancelled", "cancelled", true);
        }
      }
      // No logs or status are released across a concurrent change of grant.
      if (job.workspace) await checkWorkspaceGrant(this.env.DB, target);
      else await checkTarget(this.env.DB, target);
      const current = this.readJob()!;
      if (current.status !== "expired" && current.expiresAt !== null && Date.now() >= current.expiresAt) {
        this.expire(current);
        return this.response(this.readJob()!, action, args);
      }
      return this.response(current, action, args);
    } catch (error) {
      if (error instanceof RangeError) return Response.json({ error: "Invalid output cursor or page size" }, { status: 400 });
      if (error instanceof OperationError) return Response.json({ error: error.message }, { status: error.status });
      throw error;
    }
  }

  private async recoverOrExpire(job: Job) {
    if (job.status === "running" && !this.execution) {
      await this.finish(job, job.dispatched ? "unknown" : "failed", "executor_restarted", false);
    } else if (job.status !== "expired" && job.expiresAt !== null && Date.now() >= job.expiresAt) {
      this.expire(job);
    }
  }

  async alarm(): Promise<boolean> {
    const job = this.readJob();
    if (!job) return false; // Web terminal status alarm on a different instance.
    if (job.status !== "queued") {
      await this.recoverOrExpire(job);
      // An early delivery, including a retry, must keep the retention alarm.
      const current = this.readJob()!;
      if (current.status !== "expired" && current.expiresAt !== null) await this.storage.setAlarm(current.expiresAt);
      return true;
    }
    if (Date.now() >= job.deadline) {
      await this.finish(job, "timeout", "timeout", true);
      return true;
    }
    if (!job.workspace && !job.batch && !isMcpDiagnostic(job.diagnostic)) {
      await this.finish(job, "failed", "could_not_start", true);
      return true;
    }
    const controller = new AbortController();
    this.execution = controller;
    job.status = "running";
    this.save(job);
    try {
      await this.execute(job, controller);
    } finally {
      this.execution = undefined;
    }
    return true;
  }

  private async execute(job: Job, controller: AbortController) {
    let session: SSHSession | undefined;
    let forceClose: ReturnType<typeof setTimeout> | undefined;
    let stopReason: StopReason | undefined;
    const stop = (reason: StopReason) => { stopReason ??= reason; controller.abort(); };
    const timeout = setTimeout(() => stop("timeout"), Math.max(0, job.deadline - Date.now()));
    const resolveCommand = async (verifyLease: boolean) => {
      if (job.workspace) {
        await checkWorkspaceGrant(this.env.DB, job.target);
        if (verifyLease) await checkWorkspaceLease(this.env.DB, job.target, job.id, job.timeoutMs);
        return workspaceShellCommand(validateWorkspaceCommand(job.workspace.command), job.timeoutMs);
      }
      if (!job.batch) {
        if (!isMcpDiagnostic(job.diagnostic)) throw new OperationError("Diagnostic unavailable");
        await checkTarget(this.env.DB, job.target);
        return fixedDiagnosticCommand(job.diagnostic);
      }
      await checkBatchPosition(this.env, job.target, job.id, job.batch);
      const approved = await readApprovedBatch(this.env.DB, job.target, job.batch.batchId, job.batch.digest, this.env.TERNSSH_APPROVER_SHA256);
      const command = approved.commands[job.batch.index];
      if (typeof command !== "string" || !command || approved.timeoutMs !== job.timeoutMs) {
        throw new OperationError("Approved item unavailable");
      }
      return command;
    };
    let command: string | undefined;
    const check = async (verifyLease = true) => {
      controller.signal.throwIfAborted();
      if (await resolveCommand(verifyLease) !== command) throw new OperationError("Command approval changed");
      controller.signal.throwIfAborted();
    };
    let checking = false;
    const monitor = setInterval(async () => {
      if (checking) return;
      checking = true;
      try {
        if (job.batch && job.dispatched) await checkBatchPosition(this.env, job.target, job.id, job.batch);
        else if (job.workspace && job.dispatched) await checkWorkspaceGrant(this.env.DB, job.target);
        else await check(false);
      } catch { stop("authorization_changed"); } finally { checking = false; }
    }, 20_000);
    const abort = () => {
      if (!session || !job.dispatched) { session?.close(); return; }
      // Give a cooperative peer a brief opportunity to report TERM and final output.
      // A disconnected peer can leave the remote process outcome unknown.
      forceClose = setTimeout(() => session?.close(), 1000);
      void session.requestExecTermination().catch(() => session?.close());
    };
    controller.signal.addEventListener("abort", abort, { once: true });
    let status: JobStatus;
    let reason: Reason | null = null;
    let outputEnded = false;
    try {
      await this.storage.sync();
      command = await resolveCommand(true);
      session = await this.connect(this.env.DB, job.target, check, controller.signal);
      controller.signal.throwIfAborted();
      const result = await session.execCommand(command, Math.max(1, job.deadline - Date.now()) + 1500, async () => {
        await check();
        // Commit the send boundary before allowing the first SSH exec packet onto the network.
        job.dispatched = true;
        this.save(job);
        await this.storage.sync();
        await check();
      }, Infinity, (stream, data) => this.output().append(stream, data));
      job.exitCode = result.exitCode;
      reason = this.readJob()?.reason ?? stopReason ?? null;
      status = reason === "cancelled" || reason === "timeout" ? reason :
        result.exitCode === 0 ? "completed" : "failed";
      outputEnded = true;
    } catch (error) {
      reason = this.readJob()?.reason ?? stopReason ?? (job.dispatched ? "connection_lost" : "could_not_start");
      if (error instanceof McpSshError && error.timedOut) reason = "timeout";
      if (error instanceof OperationError) reason = "authorization_changed";
      if (error instanceof ExecCompletionError) {
        job.exitCode = error.exitCode;
        job.signal = error.signal;
        if (error.timedOut) reason = "timeout";
        outputEnded = error.outputEnded;
        if (outputEnded && reason === "connection_lost") {
          reason = error.signal !== null ? null : "no_exit_status";
        }
      }
      const known = job.exitCode !== null || job.signal !== null;
      status = job.dispatched && !known ? "unknown" :
        reason === "timeout" || reason === "cancelled" ? reason : "failed";
    } finally {
      clearTimeout(timeout);
      clearInterval(monitor);
      if (forceClose !== undefined) clearTimeout(forceClose);
      controller.signal.removeEventListener("abort", abort);
      session?.close();
    }
    await this.finish(job, status, reason, outputEnded);
  }
}
