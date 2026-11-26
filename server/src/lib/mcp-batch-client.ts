import { checkTarget, OperationError, type Target } from "../db/mcp-operations";

export interface BatchItemRef {
  batchId: string;
  digest: string;
  index: number;
}

export const batchObjectName = (target: Target, batchId: string) => `mcp-batch:${target.tokenId}:${batchId}`;

function batchStub(env: Env, target: Target, batchId: string) {
  return env.SSH_SESSION.get(env.SSH_SESSION.idFromName(batchObjectName(target, batchId)));
}

export async function callMcpBatch(
  env: Env, target: Target, batchId: string, digest: string, action: "start" | "status" | "cancel",
) {
  let result: Record<string, unknown>;
  let failed: boolean;
  try {
    const response = await batchStub(env, target, batchId).fetch(`https://mcp-batch.internal/${action}`, {
      method: "POST", body: JSON.stringify({ target, batchId, digest }),
    });
    result = await response.json<Record<string, unknown>>();
    failed = !response.ok;
    if (failed) result.code = response.status;
  } catch {
    result = { batchId, status: "unknown", error: "Batch reply unavailable; reconcile the same batch ID." };
    failed = true;
  }
  await checkTarget(env.DB, target);
  return { result, failed };
}

// In addition to the D1 approval, a child needs the coordinator's current
// position. This prevents starting a later item by guessing its job ID.
export async function checkBatchPosition(env: Env, target: Target, jobId: string, ref: BatchItemRef) {
  const response = await batchStub(env, target, ref.batchId).fetch("https://mcp-batch.internal/position", {
    method: "POST", body: JSON.stringify({ target, jobId, ...ref }),
  });
  if (response.status !== 204) throw new OperationError("Batch item is no longer authorized");
}
