import { purgeExpiredCommandBatches } from "../db/mcp-command-batches";
import { OperationError } from "../db/mcp-operations";

const name = "mcp-maintenance:batch-expiry";
const origin = "https://mcp-expiry.internal";
const intervalMs = 15 * 60 * 1000;

// Arm before writing a proposal. The singleton sweeps the two expiry indexes
// even if the caller disappears between D1 commit and coordinator handoff.
export async function ensureBatchExpiryAlarm(env: Env) {
  const namespace = env.SSH_SESSION;
  const reply = await namespace.get(namespace.idFromName(name)).fetch(origin + "/arm", { method: "POST" });
  if (reply.status !== 204) throw new OperationError("Batch expiry service unavailable", 503);
}

export class McpBatchExpiry {
  constructor(private readonly ctx: DurableObjectState, private readonly env: Env) {}

  private isExpiryObject() { return this.ctx.id.equals(this.env.SSH_SESSION.idFromName(name)); }

  async fetch(request: Request) {
    if (!this.isExpiryObject() || request.method !== "POST" || request.url !== origin + "/arm") {
      return new Response(null, { status: 404 });
    }
    if (await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(Date.now() + intervalMs);
    return new Response(null, { status: 204 });
  }

  async alarm(): Promise<boolean> {
    if (!this.isExpiryObject()) return false;
    // Install the next wake-up before contacting D1 so a temporary outage or
    // process restart doesn't leave an idle deployment without a cleaner.
    await this.ctx.storage.setAlarm(Date.now() + intervalMs);
    await purgeExpiredCommandBatches(this.env.DB);
    return true;
  }
}
