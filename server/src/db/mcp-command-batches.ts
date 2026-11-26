import { digestToken } from "./mcp-access";
import { OperationError, type Target } from "./mcp-operations";

export const COMMAND_BATCH_POLICY = "sequential_independent_stop_on_failure_or_unknown";
export const COMMAND_BATCH_LIMITS = {
  commands: 16, commandBytes: 4096, totalBytes: 8192,
  defaultTimeoutMs: 120_000, minTimeoutMs: 1000, maxTimeoutMs: 600_000,
  ttlSeconds: 900, activePerToken: 32, receiptsPerToken: 8192,
} as const;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const encoder = new TextEncoder();
const purge = "UPDATE mcp_command_batches SET commands=NULL WHERE commands IS NOT NULL AND expires<=unixepoch()";

export interface CommandBatchInput {
  batchId: string;
  commands: string[];
  timeoutMs?: number;
}
export interface CommandBatchProposal {
  version: 1;
  status: "proposed";
  policy: typeof COMMAND_BATCH_POLICY;
  batchId: string;
  serverId: string;
  serverName: string;
  revision: number;
  identityVersion: string;
  commands: string[];
  timeoutMs: number;
  digest: string;
  challenge: string;
  expiresAt: number;
}

function checkId(id: string) {
  if (typeof id !== "string" || !uuid.test(id)) throw new OperationError("Invalid batch ID", 400);
}

function snapshot(input: CommandBatchInput) {
  checkId(input.batchId);
  const limits = COMMAND_BATCH_LIMITS;
  const timeoutMs = input.timeoutMs === undefined ? limits.defaultTimeoutMs : input.timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < limits.minTimeoutMs || timeoutMs > limits.maxTimeoutMs) {
    throw new OperationError("Invalid per-command timeout", 400);
  }
  if (!Array.isArray(input.commands) || !input.commands.length || input.commands.length > limits.commands) {
    throw new OperationError("Invalid number of commands", 400);
  }
  const commands = Array.from(input.commands);
  let bytes = 0;
  for (const command of commands) {
    // Preserve LF, CRLF and tabs. Reject terminal escapes, bidi overrides,
    // bare carriage returns and code units that cannot round-trip through UTF-8.
    if (typeof command !== "string" || !command.trim() ||
        /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\uD800-\uDFFF]|\r(?!\n)/u.test(command)) {
      throw new OperationError("Invalid command text", 400);
    }
    const length = encoder.encode(command).length;
    bytes += length;
    if (length > limits.commandBytes || bytes > limits.totalBytes) throw new OperationError("Batch is too large", 413);
  }
  const body = JSON.stringify(commands);
  // Leave space for JSON-RPC and target identifiers under the 16 KiB transport limit.
  if (encoder.encode(body).length > 12 * 1024) throw new OperationError("Encoded batch is too large", 413);
  return { batchId: input.batchId, commands, body, timeoutMs };
}

function storageError(): never {
  // D1 diagnostics may include query details. Never attach them to a tool result or log.
  throw new Error("Command proposal storage unavailable");
}

// Safe to invoke independently from a maintenance alarm. Prepare and read
// also erase expired bodies. Access expires at database time even while idle.
export async function purgeExpiredCommandBatches(db: D1Database): Promise<number> {
  const [proposals, approvals] = await db.batch([
    db.prepare(purge),
    db.prepare("UPDATE mcp_batch_approvals SET commands=NULL WHERE commands IS NOT NULL AND expires_at<=unixepoch()*1000"),
  ]).catch(storageError);
  return proposals.meta.changes + approvals.meta.changes;
}

type BatchRow = {
  currentName: string;
  serverName: string | null;
  reserved: number;
  commands: string | null;
  timeoutMs: number | null;
  digest: string | null;
  challenge: string | null;
  expiresAt: number | null;
};

function lookup(db: D1DatabaseSession, target: Target, id: string) {
  return db.prepare(`
    SELECT s.name AS currentName, b.server_name AS serverName, b.timeout_ms AS timeoutMs,
      b.digest, b.challenge, b.expires * 1000 AS expiresAt,
      CASE WHEN b.expires > unixepoch() THEN b.commands END AS commands,
      EXISTS(SELECT 1 FROM mcp_command_batches WHERE token_id=g.token_id AND batch_id=?1) AS reserved
    FROM mcp_active_targets g JOIN servers s ON s.id=g.server_id AND s.user_id=g.user_id
    LEFT JOIN mcp_command_batches b ON b.token_id=g.token_id AND b.batch_id=?1 AND b.user_id=g.user_id
      AND b.server_id=g.server_id AND b.identity_version=g.identity_version AND b.revision=g.revision
    WHERE g.user_id=?2 AND g.token_id=?3 AND g.server_id=?4 AND g.revision=?5 AND g.identity_version=?6
  `).bind(id, target.userId, target.tokenId, target.serverId, target.revision, target.identityVersion);
}

function proposal(target: Target, id: string, row?: BatchRow | null): CommandBatchProposal {
  if (!row) throw new OperationError("Authorization changed", 403);
  if (row.digest === null || row.challenge === null || row.serverName === null || row.timeoutMs === null || row.expiresAt === null) {
    throw new OperationError("Proposal unavailable", 404);
  }
  if (row.commands === null) throw new OperationError("Proposal expired", 410);
  return {
    version: 1, status: "proposed", policy: COMMAND_BATCH_POLICY,
    batchId: id, serverId: target.serverId, serverName: row.serverName,
    revision: target.revision, identityVersion: target.identityVersion,
    commands: JSON.parse(row.commands), timeoutMs: row.timeoutMs, digest: row.digest, challenge: row.challenge, expiresAt: row.expiresAt,
  };
}

export async function readCommandBatch(db: D1Database, target: Target, id: string): Promise<CommandBatchProposal> {
  checkId(id);
  const database = db.withSession("first-primary");
  const [, result] = await database.batch<BatchRow>([database.prepare(purge), lookup(database, target, id)])
    .catch(storageError);
  return proposal(target, id, result.results[0]);
}

export async function prepareCommandBatch(
  db: D1Database, target: Target, input: CommandBatchInput,
): Promise<CommandBatchProposal> {
  const { batchId, commands, body, timeoutMs } = snapshot(input);
  const database = db.withSession("first-primary");
  const existing = await lookup(database, target, batchId).first<BatchRow>().catch(storageError);
  if (!existing) throw new OperationError("Authorization changed", 403);
  if (existing.reserved && !existing.digest) throw new OperationError("Batch ID already reserved", 409);
  // The display name is frozen on first use. Renaming a server does not
  // mutate a pending proposal or change the result of retrying that proposal.
  const name = existing.serverName ?? existing.currentName;
  const digest = await digestToken(JSON.stringify(["ternssh/mcp-command-batch", 1, COMMAND_BATCH_POLICY,
    target.userId, target.tokenId, target.serverId, target.revision, target.identityVersion,
    name, batchId, timeoutMs, commands]));
  const limits = COMMAND_BATCH_LIMITS;
  const insert = database.prepare(`
    INSERT INTO mcp_command_batches
      (token_id,batch_id,user_id,server_id,server_name,revision,identity_version,timeout_ms,digest,commands,expires)
    SELECT g.token_id,?1,g.user_id,g.server_id,s.name,g.revision,g.identity_version,?2,?3,?4,unixepoch()+?5
    FROM mcp_active_targets g JOIN servers s ON s.id=g.server_id AND s.user_id=g.user_id
    WHERE g.user_id=?6 AND g.token_id=?7 AND g.server_id=?8 AND g.revision=?9 AND g.identity_version=?10 AND s.name=?11
      AND NOT EXISTS(SELECT 1 FROM mcp_command_batches WHERE token_id=?7 AND batch_id=?1)
      AND NOT EXISTS(SELECT 1 FROM mcp_command_batches WHERE token_id=?7 AND commands IS NOT NULL LIMIT 1 OFFSET ?12)
      AND NOT EXISTS(SELECT 1 FROM mcp_command_batches WHERE token_id=?7 LIMIT 1 OFFSET ?13)
  `).bind(batchId, timeoutMs, digest, body, limits.ttlSeconds, target.userId, target.tokenId, target.serverId,
    target.revision, target.identityVersion, name, limits.activePerToken - 1, limits.receiptsPerToken - 1);
  // The current grant, quotas and reservation are checked in the primary write.
  // The final lookup cannot return a different pairing's or revision's body.
  const [, , result] = await database.batch<BatchRow>([database.prepare(purge), insert, lookup(database, target, batchId)])
    .catch(storageError);
  const row = result.results[0];
  if (!row) throw new OperationError("Authorization changed", 403);
  if (row.reserved && row.digest !== digest) throw new OperationError("Batch ID already reserved", 409);
  if (row.currentName !== name && !row.reserved) throw new OperationError("Server name changed", 409);
  if (!row.reserved) throw new OperationError("Proposal capacity reached", 429);
  return proposal(target, batchId, row);
}
