import { readCommandBatch, type CommandBatchProposal } from "./mcp-command-batches";
import { OperationError, type Target } from "./mcp-operations";

const algorithm = { name: "ECDSA", namedCurve: "P-256" };
const encode = (s: string) => new TextEncoder().encode(s);
const toBase64 = (a: Uint8Array) => btoa(String.fromCharCode(...a));
const hex = (a: ArrayBuffer) => Array.from(new Uint8Array(a), n => n.toString(16).padStart(2, "0")).join("");

function decodeFixed(input: string, length: number): Uint8Array<ArrayBuffer> {
  if (typeof input !== "string" || input.length !== 4 * Math.ceil(length / 3) || !/^[A-Za-z0-9+/]+={0,2}$/.test(input)) {
    throw new OperationError("Invalid approval data", 400);
  }
  const bytes = Uint8Array.from(atob(input), c => c.charCodeAt(0));
  if (bytes.length !== length || toBase64(bytes) !== input) throw new OperationError("Invalid approval data", 400);
  return bytes;
}

async function importKey(spki: string) {
  const bytes = decodeFixed(spki, 91);
  try {
    const key = await crypto.subtle.importKey("spki", bytes, algorithm, true, ["verify"]);
    const canonical = await crypto.subtle.exportKey("spki", key);
    if (!(canonical instanceof ArrayBuffer) || toBase64(new Uint8Array(canonical)) !== spki) throw new Error();
    return { key, fingerprint: hex(await crypto.subtle.digest("SHA-256", bytes)) };
  } catch {
    throw new OperationError("Expected a P-256 approval public key", 400);
  }
}

function requireTrustedSigner(pin: string | undefined) {
  if (!pin || !/^[a-f0-9]{64}$/.test(pin)) throw new OperationError("Local batch approval is not enabled for this deployment", 403);
  return pin;
}

// A spent receipt outlives both copies of the command text. Reconciliation
// may inspect its existence but must never use it to authorize a new start.
export async function hasApprovalReceipt(db: D1Database, target: Target, batchId: string, digest: string) {
  const found = await db.withSession("first-primary").prepare(`SELECT 1 AS found
    FROM mcp_batch_approvals a JOIN mcp_command_batches b USING(token_id,batch_id,digest)
    JOIN mcp_active_targets g ON g.user_id=b.user_id AND g.token_id=b.token_id AND g.server_id=b.server_id
      AND g.revision=b.revision AND g.identity_version=b.identity_version
    WHERE g.user_id=? AND g.token_id=? AND g.server_id=? AND g.revision=? AND g.identity_version=?
      AND a.batch_id=? AND a.digest=?`)
    .bind(target.userId,target.tokenId,target.serverId,target.revision,target.identityVersion,batchId,digest).first("found");
  return found === 1;
}

export async function registerApprovalKey(db: D1Database, userId: string, tokenId: string, spki: string, pin: string | undefined) {
  const { fingerprint } = await importKey(spki);
  if (requireTrustedSigner(pin) !== fingerprint) throw new OperationError("The deployment does not trust this approval key", 403);
  const saved = await db.prepare(`INSERT INTO mcp_batch_keys(token_id,spki,fingerprint)
    SELECT id,?3,?4 FROM mcp_tokens WHERE id=?1 AND user_id=?2 ON CONFLICT(token_id) DO NOTHING`)
    .bind(tokenId, userId, spki, fingerprint).run();
  if (!saved.meta.changes) throw new OperationError("Pairing unavailable or already enrolled", 409);
  return { fingerprint };
}

function approvalBytes(origin: string, target: Target, p: CommandBatchProposal) {
  return encode(JSON.stringify(["ternssh/batch-approval", 1, origin, target.userId, target.tokenId,
    target.serverId, p.serverName, target.identityVersion, target.revision, p.batchId, p.timeoutMs,
    p.policy, p.commands, p.digest, p.challenge, p.expiresAt]));
}

export async function describeApproval(db: D1Database, origin: string, target: Target, proposal: CommandBatchProposal, pin: string | undefined) {
  const key = await db.withSession("first-primary").prepare("SELECT fingerprint FROM mcp_batch_keys WHERE token_id=?")
    .bind(target.tokenId).first<{fingerprint:string}>();
  const fingerprint = key?.fingerprint && key.fingerprint === pin ? key.fingerprint : null;
  return { ...proposal, approvalKeyFingerprint: fingerprint,
    approvalPayloadBase64: fingerprint ? toBase64(approvalBytes(origin, target, proposal)) : null };
}

// The caller supplies a detached signature only. The write takes the command
// snapshot from the primary database and rechecks grant, key, expiry and nonce.
export async function acceptSignedBatch(db: D1Database, origin: string, target: Target, batchId: string, digest: string, signature: string, pin: string | undefined) {
  const trusted = requireTrustedSigner(pin);
  const proposal = await readCommandBatch(db, target, batchId).catch(async error => {
    if (error instanceof OperationError && error.status === 410 && await hasApprovalReceipt(db, target, batchId, digest)) {
      throw new OperationError("Approval already consumed; query the batch ID", 409);
    }
    throw error;
  });
  if (proposal.digest !== digest) throw new OperationError("Proposal changed", 409);
  const database = db.withSession("first-primary");
  const row = await database.prepare("SELECT spki,fingerprint FROM mcp_batch_keys WHERE token_id=?")
    .bind(target.tokenId).first<{spki:string;fingerprint:string}>();
  if (!row) throw new OperationError("No approval key registered for this pairing", 403);
  const { key, fingerprint } = await importKey(row.spki);
  if (fingerprint !== trusted || fingerprint !== row.fingerprint || !await crypto.subtle.verify({ name:"ECDSA", hash:"SHA-256" },
      key, decodeFixed(signature, 64), approvalBytes(origin, target, proposal))) {
    throw new OperationError("Batch signature did not verify", 403);
  }
  const lifetimeMs = Math.min(2 * 60 * 60 * 1000, proposal.commands.length * (proposal.timeoutMs + 10000) + 60000);
  const saved = await database.prepare(`INSERT INTO mcp_batch_approvals(token_id,batch_id,digest,fingerprint,commands,expires_at)
    SELECT b.token_id,b.batch_id,b.digest,k.fingerprint,b.commands,unixepoch()*1000+?10
    FROM mcp_command_batches b JOIN mcp_batch_keys k ON k.token_id=b.token_id
    JOIN mcp_active_targets g ON g.token_id=b.token_id AND g.user_id=b.user_id AND g.server_id=b.server_id
      AND g.revision=b.revision AND g.identity_version=b.identity_version
    WHERE b.token_id=?1 AND b.user_id=?2 AND b.server_id=?3 AND b.identity_version=?4 AND b.revision=?5
      AND b.batch_id=?6 AND b.digest=?7 AND b.challenge=?8 AND k.fingerprint=?9
      AND b.commands IS NOT NULL AND b.expires>unixepoch()
    ON CONFLICT(token_id,batch_id) DO NOTHING`).bind(target.tokenId,target.userId,target.serverId,
      target.identityVersion,target.revision,batchId,digest,proposal.challenge,fingerprint,lifetimeMs).run();
  if (!saved.meta.changes) {
    // A previously consumed signature is never another start instruction.
    throw new OperationError("Approval unavailable or already consumed; query the batch ID", 409);
  }
}

export async function readApprovedBatch(db: D1Database, target: Target, batchId: string, digest: string, pin: string | undefined) {
  const trusted = requireTrustedSigner(pin);
  const row = await db.withSession("first-primary").prepare(`SELECT a.commands,b.timeout_ms AS timeoutMs,a.expires_at AS expiresAt
    FROM mcp_batch_approvals a JOIN mcp_command_batches b ON b.token_id=a.token_id AND b.batch_id=a.batch_id AND b.digest=a.digest
    JOIN mcp_batch_keys k ON k.token_id=a.token_id AND k.fingerprint=a.fingerprint
    JOIN mcp_active_targets g ON g.token_id=b.token_id AND g.user_id=b.user_id AND g.server_id=b.server_id
      AND g.revision=b.revision AND g.identity_version=b.identity_version
    WHERE g.user_id=? AND g.token_id=? AND g.server_id=? AND g.revision=? AND g.identity_version=?
      AND a.batch_id=? AND a.digest=? AND k.fingerprint=? AND a.expires_at>unixepoch()*1000 AND a.commands IS NOT NULL`)
    .bind(target.userId,target.tokenId,target.serverId,target.revision,target.identityVersion,batchId,digest,trusted)
    .first<{commands:string;timeoutMs:number;expiresAt:number}>();
  if (!row) throw new OperationError("No current approval for this batch", 403);
  return { commands: JSON.parse(row.commands) as string[], timeoutMs: row.timeoutMs, expiresAt: row.expiresAt };
}

export async function eraseApprovedCommands(db: D1Database, target: Target, batchId: string, digest: string) {
  await db.batch([
    db.prepare("UPDATE mcp_batch_approvals SET commands=NULL WHERE token_id=? AND batch_id=? AND digest=? AND commands IS NOT NULL")
      .bind(target.tokenId,batchId,digest),
    db.prepare("UPDATE mcp_command_batches SET commands=NULL WHERE token_id=? AND batch_id=? AND digest=? AND commands IS NOT NULL")
      .bind(target.tokenId,batchId,digest),
  ]);
}
