import { checkTarget, type Target } from "../db/mcp-operations";
import { checkWorkspaceGrant } from "../db/mcp-access";
import type { JobStream } from "./mcp-job-output";
import type { McpDiagnostic } from "./mcp-ssh";

type JobRequest =
  | { action: "start" | "reconcile"; diagnostic: McpDiagnostic; timeoutMs: number }
  | { action: "workspace-start" | "workspace-reconcile"; command: string; timeoutMs: number }
  | { action: "status" | "cancel" }
  | { action: "read"; cursor?: number; limit?: number }
  | { action: "tail"; stream?: JobStream; limit?: number };

export async function callMcpJob(env: Env, target: Target, jobId: string, request: JobRequest) {
  const { action, ...options } = request;
  const namespace = env.SSH_SESSION;
  const stub = namespace.get(namespace.idFromName(`mcp-job:${target.tokenId}:${jobId}`));
  let result: Record<string, unknown>;
  let failed: boolean;
  try {
    const response = await stub.fetch(`https://mcp-job.internal/${action}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, jobId, ...options }),
    });
    const payload = await response.json<Record<string, unknown>>();
    // Keep cursor and state visible even in clients that clip a long text result.
    const { frames, streamTail, ...metadata } = payload;
    result = metadata;
    if (frames !== undefined) result.frames = frames;
    if (streamTail !== undefined) result.streamTail = streamTail;
    failed = !response.ok;
    if (failed) result.code = response.status;
  } catch {
    // A lost reply does not identify which side of the dispatch boundary was reached.
    const submitting = action === "start" || action === "workspace-start" || action === "workspace-reconcile";
    result = { jobId, status: submitting ? "unknown" : "unavailable",
      error: "Job response unavailable. Query this job ID to reconcile its state." };
    failed = true;
  }
  if (action === "workspace-start" || action === "workspace-reconcile" || result.environment === "isolated_workspace") {
    await checkWorkspaceGrant(env.DB, target);
  } else {
    await checkTarget(env.DB, target);
  }
  return { result, failed };
}
