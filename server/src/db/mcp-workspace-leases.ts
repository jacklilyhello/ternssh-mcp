import { checkWorkspaceGrant } from "./mcp-access";
import { OperationError, type Target } from "./mcp-operations";

// Include time for a queued alarm, SSH setup and remote watchdog cleanup.
const startupGraceSeconds = 120;
const teardownGraceSeconds = 15;
const maxConcurrent = 2;
const maxPerHour = 64;

export async function reserveWorkspaceRequest(db: D1Database, target: Target, id: string, timeoutMs: number) {
  await checkWorkspaceGrant(db, target);
  const database = db.withSession("first-primary");
  const [insert, lookup] = await database.batch<{ workspace_server_id: string | null }>([
    database.prepare(`INSERT INTO mcp_diagnostic_requests
      (token_id, request_id, workspace_server_id, workspace_started_at, workspace_lease_until)
      SELECT g.token_id, ?1, g.server_id, unixepoch(), unixepoch() + ?2 FROM mcp_active_targets g
      WHERE g.token_id=?3 AND g.user_id=?4 AND g.server_id=?5 AND g.revision=?6 AND g.identity_version=?7
        AND NOT EXISTS (SELECT 1 FROM mcp_diagnostic_requests WHERE workspace_server_id=?5
          AND workspace_lease_until > unixepoch() LIMIT 1 OFFSET ?8)
        AND NOT EXISTS (SELECT 1 FROM mcp_diagnostic_requests WHERE workspace_server_id=?5
          AND workspace_started_at > unixepoch()-3600 LIMIT 1 OFFSET ?9)
      ON CONFLICT(token_id,request_id) DO NOTHING`).bind(id,
        Math.ceil(timeoutMs / 1000) + startupGraceSeconds + teardownGraceSeconds,
        target.tokenId, target.userId, target.serverId, target.revision, target.identityVersion,
        maxConcurrent - 1, maxPerHour - 1),
    database.prepare("SELECT workspace_server_id FROM mcp_diagnostic_requests WHERE token_id=? AND request_id=?")
      .bind(target.tokenId, id),
  ]);
  if (insert.meta.changes) return "workspace-start";
  const existing = lookup.results[0];
  if (existing?.workspace_server_id === target.serverId) return "workspace-reconcile";
  if (existing) throw new OperationError("Request ID already reserved for another operation", 409);
  await checkWorkspaceGrant(db, target);
  throw new OperationError("Workspace job limit reached for this server", 429);
}

export async function checkWorkspaceLease(db: D1Database, target: Target, id: string, timeoutMs: number) {
  const row = await db.withSession("first-primary").prepare(`SELECT 1 FROM mcp_diagnostic_requests
    WHERE token_id=? AND request_id=? AND workspace_server_id=? AND workspace_lease_until>=unixepoch()+?`)
    .bind(target.tokenId, id, target.serverId, Math.ceil(timeoutMs / 1000) + teardownGraceSeconds).first();
  if (!row) throw new OperationError("Workspace startup lease expired", 410);
}

export async function releaseWorkspaceLease(db: D1Database, target: Target, id: string) {
  await db.prepare(`UPDATE mcp_diagnostic_requests SET workspace_lease_until=NULL
    WHERE token_id=? AND request_id=? AND workspace_server_id=?`).bind(target.tokenId, id, target.serverId).run();
}
