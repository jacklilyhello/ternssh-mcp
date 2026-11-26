import { OperationError, type Target } from "./mcp-operations";

export interface McpSelection {
  id: string;
  identityVersion: string;
  workspaceShell?: boolean;
}

interface AvailableServer extends McpSelection {
  name: string;
  mode: "workspace" | "selected" | null;
}

interface TokenMetadata {
  id: string;
  createdAt: string;
}

interface RecentCall {
  at: string;
  target: string | null;
  result: "listed" | "completed" | "failed" | "timeout" | "unknown" | "uploaded" | "downloaded";
}

const TOKEN_PATTERN = /^tmcp_[a-zA-Z0-9_-]{43}$/;
const workspaceEnabled = "json_type(item.value, '$.workspaceShell') = 'true'";
const authorizedHosts = `FROM mcp_tokens t
  JOIN mcp_authorizations a ON a.user_id = t.user_id
  JOIN json_each(a.selection) item
  JOIN servers s ON s.id = item.value ->> '$.id' AND s.user_id = t.user_id
  JOIN mcp_target_identities i ON i.server_id = s.id AND i.version = item.value ->> '$.identityVersion'`;

export async function checkWorkspaceGrant(db: D1Database, target: Target): Promise<void> {
  const allowed = await db.withSession("first-primary").prepare(`
    SELECT 1 AS allowed ${authorizedHosts}
    WHERE t.id = ? AND t.user_id = ? AND s.id = ? AND i.version = ? AND a.revision = ? AND ${workspaceEnabled}
  `).bind(target.tokenId, target.userId, target.serverId, target.identityVersion, target.revision).first();
  if (!allowed) throw new OperationError("Workspace command access is not authorized", 403);
}

export async function digestToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function getMcpAccessState(db: D1Database, userId: string) {
  const database = db.withSession("first-primary");
  const [scope, candidates, tokens, calls] = await database.batch<Record<string, unknown>>([
    database.prepare("SELECT revision FROM mcp_authorizations WHERE user_id = ?").bind(userId),
    database.prepare(`
      SELECT s.id, s.name, i.version AS identityVersion, (
        SELECT CASE WHEN ${workspaceEnabled} THEN 'workspace' ELSE 'selected' END
        FROM mcp_authorizations a, json_each(a.selection) item
        WHERE a.user_id = s.user_id AND item.value ->> '$.id' = s.id
          AND item.value ->> '$.identityVersion' = i.version
      ) AS mode
      FROM servers s JOIN mcp_target_identities i ON i.server_id = s.id
      WHERE s.user_id = ? ORDER BY s.name COLLATE NOCASE, s.id
    `).bind(userId),
    database.prepare(`
      SELECT t.id, t.created_at AS createdAt, k.fingerprint AS approvalKeyFingerprint FROM mcp_tokens t
      LEFT JOIN mcp_batch_keys k ON k.token_id=t.id WHERE t.user_id = ?
      ORDER BY t.created_at DESC, t.id
    `).bind(userId),
    database.prepare(`
      SELECT at, target, result FROM mcp_recent_calls WHERE user_id = ?
      ORDER BY id DESC LIMIT 20
    `).bind(userId),
  ]);

  const servers = candidates.results as unknown as AvailableServer[];
  const pairings = tokens.results as unknown as (TokenMetadata & { approvalKeyFingerprint: string | null })[];
  return {
    revision: Number(scope.results[0]?.revision ?? 0),
    availableServers: servers.map(({ id, name, identityVersion, mode }) =>
      ({ id, name, identityVersion, ...(mode === "workspace" && { workspaceShell: true }) })),
    authorizedServerIds: servers.filter((server) => server.mode !== null).map((server) => server.id),
    tokens: pairings.map(({ id, createdAt, approvalKeyFingerprint }) =>
      approvalKeyFingerprint ? { id, createdAt, approvalKeyFingerprint } : { id, createdAt }),
    recentCalls: calls.results as unknown as RecentCall[],
  };
}

export async function replaceMcpAuthorization(
  db: D1Database, userId: string, revision: number, servers: McpSelection[],
): Promise<boolean> {
  // The revision check, owner/identity checks and entire replacement share one SQLite write.
  const selection = JSON.stringify(servers);
  const result = await db.prepare(`
    INSERT INTO mcp_authorizations (user_id, revision, selection)
    SELECT ?1, 1, ?2 WHERE ?3 = COALESCE(
      (SELECT revision FROM mcp_authorizations WHERE user_id = ?1), 0
    ) AND NOT EXISTS (
      SELECT 1 FROM json_each(?2) item WHERE NOT EXISTS (
        SELECT 1 FROM servers s JOIN mcp_target_identities i ON i.server_id = s.id
        WHERE s.user_id = ?1 AND s.id = item.value ->> '$.id'
          AND i.version = item.value ->> '$.identityVersion'
      )
    )
    ON CONFLICT(user_id) DO UPDATE SET revision = revision + 1, selection = excluded.selection
  `).bind(userId, selection, revision).run();
  // D1 includes redactions performed by the grant-change triggers in this count.
  return result.meta.changes > 0;
}

export async function endMcpAuthorization(db: D1Database, userId: string): Promise<void> {
  await db.prepare(`
    INSERT INTO mcp_authorizations (user_id, revision, selection) VALUES (?, 1, '[]')
    ON CONFLICT(user_id) DO UPDATE SET revision = revision + 1, selection = '[]'
  `).bind(userId).run();
}

export async function issueMcpToken(db: D1Database, userId: string) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const suffix = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const token = `tmcp_${suffix}`;
  const metadata = await db.prepare(`
    INSERT INTO mcp_tokens (id, user_id, digest) VALUES (?, ?, ?)
    RETURNING id, created_at AS createdAt
  `).bind(crypto.randomUUID(), userId, await digestToken(token)).first<TokenMetadata>();
  if (!metadata) throw new Error("Token creation failed");
  return { ...metadata, token };
}

export async function revokeMcpToken(db: D1Database, userId: string, id: string): Promise<boolean> {
  const removed = await db.prepare("DELETE FROM mcp_tokens WHERE user_id = ? AND id = ? RETURNING id")
    .bind(userId, id).first();
  return removed !== null;
}

export async function authenticateMcpToken(db: D1Database, rawToken: string): Promise<boolean> {
  if (!TOKEN_PATTERN.test(rawToken)) return false;
  const row = await db.withSession("first-primary")
    .prepare("SELECT 1 AS valid FROM mcp_tokens WHERE digest = ?")
    .bind(await digestToken(rawToken)).first();
  return row !== null;
}

export async function listMcpAuthorizedServers(
  db: D1Database, rawToken: string,
): Promise<Array<{ id: string; name: string; workspaceShell?: boolean }> | null> {
  if (!TOKEN_PATTERN.test(rawToken)) return null;
  const digest = await digestToken(rawToken);
  const database = db.withSession("first-primary");
  // A token always produces a row, even when its workspace has an empty grant.
  // Authentication, the current grant and the audit entry use the same snapshot.
  const [servers] = await database.batch([
    database.prepare(`
      WITH allowed AS (
        SELECT s.user_id, s.id, s.name, ${workspaceEnabled} AS workspaceShell ${authorizedHosts}
        WHERE t.digest = ?1
      )
      SELECT allowed.id, allowed.name, allowed.workspaceShell FROM mcp_tokens t
      LEFT JOIN allowed ON allowed.user_id = t.user_id WHERE t.digest = ?1
      ORDER BY allowed.name COLLATE NOCASE, allowed.id
    `).bind(digest),
    database.prepare(`
      INSERT INTO mcp_recent_calls (user_id, result)
      SELECT user_id, 'listed' FROM mcp_tokens WHERE digest = ?
    `).bind(digest),
  ]);
  const rows = servers.results as unknown as { id: string | null; name: string; workspaceShell: number | null }[];
  if (!rows.length) return null;
  return rows.flatMap(({ id, name, workspaceShell }) =>
    id === null ? [] : [{ id, name, ...(workspaceShell === 1 && { workspaceShell: true }) }]);
}
