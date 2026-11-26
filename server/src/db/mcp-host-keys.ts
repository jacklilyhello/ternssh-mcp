import { buildSSHConnectionConfig } from "../lib/ssh-connection-config";
import type { ServerRecord } from "../types";

export interface McpTarget {
  userId: string;
  serverId: string;
  identityVersion: string;
}

export async function webTargetVersion(db: D1Database, record: ServerRecord): Promise<string | null> {
  return db.withSession("first-primary").prepare(`
    SELECT i.version FROM mcp_target_identities i JOIN servers s ON s.id = i.server_id
    WHERE s.id = ? AND s.user_id = ? AND s.host = ? AND s.port = ? AND s.username = ?
  `).bind(record.id, record.user_id, record.host, record.port, record.username).first<string>("version");
}

export async function recordWebHostKey(db: D1Database, target: McpTarget, fingerprint: string): Promise<void> {
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)) throw new Error("Invalid SSH host fingerprint");
  // A late handshake cannot overwrite a newer identity, and a second key for the
  // same identity cannot silently replace the first authenticated observation.
  await db.prepare(`
    INSERT INTO mcp_host_keys (server_id, identity_version, fingerprint)
    SELECT s.id, i.version, ? FROM servers s JOIN mcp_target_identities i ON i.server_id = s.id
    WHERE s.id = ? AND s.user_id = ? AND i.version = ?
    ON CONFLICT(server_id) DO UPDATE SET identity_version = excluded.identity_version,
      fingerprint = excluded.fingerprint WHERE identity_version <> excluded.identity_version
  `).bind(fingerprint, target.serverId, target.userId, target.identityVersion).run();
}

export async function getPinnedMcpConfig(db: D1Database, target: McpTarget) {
  const row = await db.withSession("first-primary").prepare(`
    SELECT s.host, s.port, s.username, s.auth_type, c.value AS credential, k.fingerprint
    FROM servers s JOIN mcp_target_identities i ON i.server_id = s.id
    JOIN mcp_host_keys k ON k.server_id = s.id AND k.identity_version = i.version
    JOIN credentials c ON c.id = s.credential_ref AND c.user_id = s.user_id
    WHERE s.id = ? AND s.user_id = ? AND i.version = ?
  `).bind(target.serverId, target.userId, target.identityVersion).first<
    Pick<ServerRecord, "host" | "port" | "username" | "auth_type"> & { credential: string; fingerprint: string }
  >();
  if (!row || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(row.fingerprint)) return null;
  return { ...buildSSHConnectionConfig(row, row.credential), expectedFingerprint: row.fingerprint };
}
