export interface Target {
  userId: string;
  serverId: string;
  tokenId: string;
  identityVersion: string;
  revision: number;
}

export class OperationError extends Error {
  constructor(message: string, readonly status: 400 | 403 | 404 | 409 | 410 | 413 | 415 | 429 | 503 = 403) {
    super(message);
  }
}

const targetColumns = 'g.user_id AS userId, g.server_id AS serverId, g.token_id AS tokenId, g.identity_version AS identityVersion, g.revision';

export async function resolveTarget(db: D1Database, digest: string, serverId: string): Promise<Target> {
  const target = await db.withSession("first-primary").prepare(`
    SELECT ${targetColumns} FROM mcp_active_targets g JOIN mcp_tokens t ON t.id=g.token_id
    WHERE t.digest=? AND g.server_id=?`).bind(digest, serverId).first<Target>();
  if (!target) throw new OperationError("Target unavailable or authorization ended");
  return target;
}

export async function checkTarget(db: D1Database, target: Target) {
  const found = await db.withSession("first-primary").prepare(`
    SELECT 1 FROM mcp_active_targets WHERE token_id=? AND server_id=? AND revision=? AND identity_version=?
  `).bind(target.tokenId, target.serverId, target.revision, target.identityVersion).first();
  if (!found) throw new OperationError("Authorization changed");
}

export async function reserveDiagnostic(db: D1Database, target: Target, id: string) {
  const result = await db.prepare(`
    INSERT INTO mcp_diagnostic_requests (token_id,request_id)
    SELECT token_id,? FROM mcp_active_targets WHERE token_id=? AND server_id=? AND revision=? AND identity_version=?
    ON CONFLICT DO NOTHING
  `).bind(id, target.tokenId, target.serverId, target.revision, target.identityVersion).run();
  if (!result.meta.changes) throw new OperationError("Request unavailable or already dispatched; do not retry", 409);
}

export type AuditResult = "completed" | "failed" | "unknown" | "timeout" | "uploaded" | "downloaded";
export async function recordResult(db: D1Database, target: Target, result: AuditResult) {
  await db.prepare(`
    INSERT INTO mcp_recent_calls (user_id,target,result)
    SELECT user_id,name,? FROM servers WHERE id=? AND user_id=?
  `).bind(result, target.serverId, target.userId).run();
}

interface StoredFile {
  storageId: string;
  bytes: number;
  sha256: string;
}
export type NewTransfer = {direction: "upload"; bytes: number; sha256: string; replaceFileId?: string}
  | {direction: "download"; fileId: string};

export async function prepareTransfer(db: D1Database, target: Target, input: NewTransfer) {
  const database = db.withSession("first-primary");
  const fileId = input.direction === "download" ? input.fileId : input.replaceFileId;
  let previous: StoredFile | null = null;
  if (fileId) {
    previous = await database.prepare(`
      SELECT storage_id AS storageId, bytes, sha256 FROM mcp_files
      WHERE id=? AND server_id=? AND identity_version=?
    `).bind(fileId, target.serverId, target.identityVersion).first<StoredFile>();
    if (!previous) throw new OperationError("File unavailable", 404);
  }
  const spec = input.direction === "upload" ? input : previous!;
  const storageId = input.direction === "upload" ? crypto.randomUUID() : previous!.storageId;
  const logicalId = fileId ?? crypto.randomUUID();
  const operationId = crypto.randomUUID();
  const ttl = 300;
  const [, ticket] = await database.batch([
    database.prepare("DELETE FROM mcp_transfers WHERE expires <= unixepoch()"),
    database.prepare(`
      INSERT INTO mcp_transfers (id,token_id,server_id,identity_version,revision,direction,file_id,
        storage_id,previous_id,bytes,sha256,expires)
      SELECT ?,token_id,server_id,identity_version,revision,?,?,?,?,?,?,unixepoch()+?
      FROM mcp_active_targets WHERE token_id=? AND server_id=? AND revision=? AND identity_version=?
        AND (SELECT count(*) FROM mcp_transfers WHERE token_id=? AND claimed=0)<64
    `).bind(operationId, input.direction, logicalId, storageId, previous?.storageId ?? null,
      spec.bytes, spec.sha256, ttl, target.tokenId, target.serverId, target.revision, target.identityVersion, target.tokenId),
  ]);
  if (!ticket.meta.changes) throw new OperationError("Authorization changed or too many pending transfers", 409);
  return { status: "pending_local_io", operationId, fileId: logicalId, bytes: spec.bytes, sha256: spec.sha256, expiresInSeconds: ttl };
}

export interface Transfer extends Target, StoredFile {
  id: string;
  direction: "upload" | "download";
  fileId: string;
  previousId: string | null;
  previous: StoredFile | null;
  expires: number;
}

// A prepared read or replacement targets one immutable physical version of a logical file.
const currentVersion = `(x.previous_id IS NULL AND x.direction='upload' OR EXISTS(
  SELECT 1 FROM mcp_files f WHERE f.id=x.file_id AND f.server_id=x.server_id
  AND f.identity_version=x.identity_version AND f.storage_id=x.previous_id))`;

export async function claimTransfer(db: D1Database, digest: string, id: string, direction: "upload" | "download") {
  const database = db.withSession("first-primary");
  const row = await database.prepare(`
    UPDATE mcp_transfers AS x SET claimed=1 WHERE id=? AND direction=? AND claimed=0 AND expires>unixepoch() AND ${currentVersion}
      AND EXISTS (SELECT 1 FROM mcp_active_targets g JOIN mcp_tokens t ON t.id=g.token_id
        WHERE t.digest=? AND g.token_id=x.token_id AND g.server_id=x.server_id AND g.revision=x.revision
          AND g.identity_version=x.identity_version)
    RETURNING id,direction,server_id AS serverId,token_id AS tokenId,identity_version AS identityVersion,revision,
      file_id AS fileId,storage_id AS storageId,previous_id AS previousId,bytes,sha256,expires
  `).bind(id, direction, digest).first<Omit<Transfer,"userId" | "previous">>();
  if (!row) throw new OperationError("Transfer unavailable, expired or already claimed", 409);
  const target = await resolveTarget(db, digest, row.serverId);
  const previous = direction === "upload" && row.previousId ? await database.prepare(`
    SELECT storage_id AS storageId,bytes,sha256 FROM mcp_files WHERE id=? AND server_id=? AND identity_version=? AND storage_id=?
  `).bind(row.fileId, row.serverId, row.identityVersion, row.previousId).first<StoredFile>() : null;
  if (direction === "upload" && row.previousId && !previous) throw new OperationError("File version changed", 409);
  return { ...row, userId: target.userId, previous };
}

export async function checkTransfer(db: D1Database, transfer: Transfer) {
  if (Date.now() >= transfer.expires * 1000) throw new OperationError("Transfer expired", 410);
  const found = await db.withSession("first-primary").prepare(`
    SELECT 1 FROM mcp_transfers x JOIN mcp_active_targets g ON g.token_id=x.token_id AND g.server_id=x.server_id
      AND g.identity_version=x.identity_version AND g.revision=x.revision
    WHERE x.id=? AND x.claimed=1 AND x.expires>unixepoch() AND ${currentVersion}
  `).bind(transfer.id).first();
  if (!found) throw new OperationError("Authorization or file version changed", 409);
}

export async function releaseDownload(db: D1Database, transfer: Transfer) {
  // Audit the verified remote read and make the last release decision in one primary write.
  const result = await db.prepare(`
    INSERT INTO mcp_recent_calls (user_id,target,result)
    SELECT g.user_id,s.name,'downloaded' FROM mcp_transfers x JOIN mcp_active_targets g
      ON g.token_id=x.token_id AND g.server_id=x.server_id AND g.identity_version=x.identity_version AND g.revision=x.revision
    JOIN servers s ON s.id=g.server_id AND s.user_id=g.user_id
    WHERE x.id=? AND x.direction='download' AND x.claimed=1 AND x.expires>unixepoch() AND ${currentVersion}
  `).bind(transfer.id).run();
  if (!result.meta.changes) throw new OperationError("Authorization or file version changed", 409);
}

export async function publishUpload(db: D1Database, item: Transfer) {
  // Only the issuing grant can publish. Concurrent replacement of the same logical handle has one winner.
  const result = await db.prepare(`
    INSERT INTO mcp_files (id,server_id,identity_version,storage_id,bytes,sha256)
    SELECT ?1,g.server_id,g.identity_version,?2,?3,?4 FROM mcp_active_targets g
    WHERE g.token_id=?5 AND g.server_id=?6 AND g.identity_version=?7 AND g.revision=?8
      AND unixepoch()<?9 AND EXISTS(SELECT 1 FROM mcp_transfers x WHERE x.id=?11 AND x.claimed=1 AND x.direction='upload'
        AND x.token_id=g.token_id AND x.server_id=g.server_id AND x.file_id=?1 AND x.storage_id=?2 AND ${currentVersion})
    ON CONFLICT(id) DO UPDATE SET storage_id=excluded.storage_id,bytes=excluded.bytes,sha256=excluded.sha256
      WHERE storage_id=?10 AND server_id=excluded.server_id AND identity_version=excluded.identity_version
  `).bind(item.fileId, item.storageId, item.bytes, item.sha256, item.tokenId, item.serverId,
    item.identityVersion, item.revision, item.expires, item.previousId, item.id).run();
  if (!result.meta.changes) throw new OperationError("Authorization or file version changed", 409);
}
