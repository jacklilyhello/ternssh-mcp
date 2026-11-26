// Test-only transport peer. The Worker bundle uses its real MCP authentication, ticket SQL and HTTP handler.
export const MCP_FILE_MAX_BYTES = 1024 * 1024;
export class McpSshError extends Error {}
export class McpFileCommitUnknownError extends Error {}

export async function openPinnedMcpSession(db, target, authorize) {
  await authorize();
  await db.prepare("INSERT INTO fixture_connections(server) VALUES (?)").bind(target.serverId).run();
  if (await db.prepare("SELECT mode FROM fixture_mode").first("mode") === "hold-channel") {
    let closed;
    const pending = new Promise((_resolve, reject) => { closed = () => reject(new Error("test channel was closed")); });
    return { openSftpClient: () => pending, close: closed };
  }
  return { openSftpClient: async () => db, close() {} };
}

export async function uploadMcpFile(db, spec, bytes, authorize) {
  await authorize();
  await db.prepare("INSERT INTO fixture_remote(id,data) VALUES (?,?)").bind(spec.fileId, bytes).run();
  const mode = await db.prepare("SELECT mode FROM fixture_mode").first("mode");
  if (mode === "lost-rename") throw new McpFileCommitUnknownError();
  if (mode === "replace") await db.prepare("UPDATE mcp_files SET storage_id=?").bind(crypto.randomUUID()).run();
}

export async function downloadMcpFile(db, spec, authorize) {
  await authorize();
  const data = await db.prepare("SELECT data FROM fixture_remote WHERE id=?").bind(spec.fileId).first("data");
  if (!data) throw new Error("private fixture file location");
  return Uint8Array.from(data);
}

export async function removeMcpFile(db, spec, authorize) {
  await authorize();
  await db.prepare("DELETE FROM fixture_remote WHERE id=?").bind(spec.fileId).run();
}
