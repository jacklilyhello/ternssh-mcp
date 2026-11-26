import type { SFTPClient } from "../ssh/sftp";
import {
  SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_PERMISSIONS, SSH_FILEXFER_ATTR_SIZE, SSH_FILEXFER_ATTR_UIDGID,
  SSH_FX_EOF, SSH_FX_NO_SUCH_FILE, SSH_FX_OK, SSH_FXF_CREAT, SSH_FXF_EXCL, SSH_FXF_READ, SSH_FXF_WRITE,
  SSH_FXP_ATTRS, SSH_FXP_DATA, SSH_FXP_HANDLE, SSH_FXP_STATUS, SSH_S_IFDIR, SSH_S_IFMT, SSH_S_IFREG,
  type SFTPFileAttributes,
} from "../ssh/sftp-types";
import { readUint32 } from "../ssh/utils";

export const MCP_FILE_MAX_BYTES = 1024 * 1024;
export type McpFileSpec = { fileId: string; size: number; sha256: string };
type Authorize = () => Promise<void>;
const root = "./.ternssh-mcp-files";
const chunkSize = 32 * 1024;
const recheckInterval = 128 * 1024;

export class McpFileCommitUnknownError extends Error {
  constructor() { super("The SFTP commit result is unknown."); }
}

function requireFile(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function validate(spec: McpFileSpec) {
  requireFile(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(spec.fileId)
    && Number.isSafeInteger(spec.size) && spec.size >= 0 && spec.size <= MCP_FILE_MAX_BYTES
    && /^[0-9a-f]{64}$/.test(spec.sha256), "Invalid managed file metadata.");
}

function status(packet: Uint8Array) {
  requireFile(packet.length >= 9 && packet[0] === SSH_FXP_STATUS, "Invalid SFTP status.");
  return readUint32(packet, 5);
}

function ok(packet: Uint8Array) {
  requireFile(status(packet) === SSH_FX_OK, "SFTP operation was refused.");
}

function attributes(client: SFTPClient, packet: Uint8Array) {
  requireFile(packet.length >= 9 && packet[0] === SSH_FXP_ATTRS, "SFTP attributes unavailable.");
  const bits = readUint32(packet, 5);
  const fields = [[SSH_FILEXFER_ATTR_SIZE, 8], [SSH_FILEXFER_ATTR_UIDGID, 8], [SSH_FILEXFER_ATTR_PERMISSIONS, 4], [SSH_FILEXFER_ATTR_ACMODTIME, 8]];
  const minimum = fields.reduce((length, [flag, bytes]) => length + ((bits & flag) ? bytes : 0), 9);
  requireFile(packet.length >= minimum, "Invalid SFTP attributes.");
  return client.parseAttrsResponse(packet);
}

function privateNode(attrs: SFTPFileAttributes, owner: number, mode: number) {
  requireFile(attrs.uid === owner && attrs.permissions === mode, "Managed SFTP path has unsafe ownership, type or permissions.");
}

async function directory(client: SFTPClient, path: string, owner: number) {
  privateNode(attributes(client, await client.lstat(path)), owner, SSH_S_IFDIR | 0o700);
}

async function workspace(client: SFTPClient, create: boolean) {
  const home = attributes(client, await client.lstat("."));
  requireFile(typeof home.uid === "number" && typeof home.permissions === "number"
    && (home.permissions & SSH_S_IFMT) === SSH_S_IFDIR && (home.permissions & 0o022) === 0, "SFTP starting directory is unsafe.");
  const rootNode = await client.lstat(root);
  if (rootNode[0] === SSH_FXP_STATUS && status(rootNode) === SSH_FX_NO_SUCH_FILE && create) {
    // Concurrent first uploads may both attempt mkdir. Trust only the resulting private directory.
    await client.mkdir(root, 0o700);
    await directory(client, root, home.uid);
  } else {
    privateNode(attributes(client, rootNode), home.uid, SSH_S_IFDIR | 0o700);
  }
  return home.uid;
}

function extractHandle(packet: Uint8Array) {
  requireFile(packet.length > 9 && packet.length <= 265 && packet[0] === SSH_FXP_HANDLE && readUint32(packet, 5) === packet.length - 9, "SFTP open was refused.");
  return packet.subarray(9);
}

async function verifyBytes(spec: McpFileSpec, bytes: Uint8Array) {
  requireFile(bytes.length === spec.size, "Managed file size mismatch.");
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = Array.from(hash, byte => byte.toString(16).padStart(2, "0")).join("");
  requireFile(hex === spec.sha256, "Managed file digest mismatch.");
}

async function checkedHandle(client: SFTPClient, handle: Uint8Array, owner: number, size: number) {
  const attrs = attributes(client, await client.fstat(handle));
  privateNode(attrs, owner, SSH_S_IFREG | 0o600);
  requireFile(attrs.size === size, "Unexpected SFTP file size.");
}

async function readVerified(client: SFTPClient, handle: Uint8Array, owner: number, spec: McpFileSpec, authorize: Authorize) {
  await checkedHandle(client, handle, owner, spec.size);
  const bytes = new Uint8Array(spec.size);
  let offset = 0;
  let lastCheck = 0;
  let reads = 0;
  while (offset < bytes.length) {
    requireFile(++reads <= 4 * Math.ceil(spec.size / chunkSize) + 8, "SFTP file produced too many short reads.");
    if (offset - lastCheck >= recheckInterval) {
      await authorize();
      lastCheck = offset;
    }
    const length = Math.min(chunkSize, bytes.length - offset);
    const packet = await client.readFile(handle, offset, length);
    const count = packet.length - 9;
    requireFile(packet[0] === SSH_FXP_DATA && count > 0 && count <= length && readUint32(packet, 5) === count, "Invalid or incomplete SFTP file data.");
    bytes.set(packet.subarray(9), offset);
    offset += count;
  }
  requireFile(status(await client.readFile(handle, offset, 1)) === SSH_FX_EOF, "SFTP file exceeded its expected length.");
  await checkedHandle(client, handle, owner, spec.size);
  await verifyBytes(spec, bytes);
  return bytes;
}

export async function uploadMcpFile(client: SFTPClient, spec: McpFileSpec, bytes: Uint8Array, authorize: Authorize): Promise<void> {
  validate(spec);
  await authorize();
  await verifyBytes(spec, bytes);
  const owner = await workspace(client, true);
  const dir = root + "/" + spec.fileId;
  const stage = dir + "/.incoming";
  const final = dir + "/content";
  // MKDIR is an exclusive per-ID reservation. Existing IDs are never opened for writing.
  ok(await client.mkdir(dir, 0o700));
  let ownsStage = false;
  try {
    await directory(client, dir, owner);
    const handle = extractHandle(await client.openFile(stage, SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL, 0o600));
    ownsStage = true;
    try {
      await checkedHandle(client, handle, owner, 0);
      for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        if (offset % recheckInterval === 0) await authorize();
        ok(await client.writeFile(handle, offset, bytes.subarray(offset, offset + chunkSize)));
      }
      await readVerified(client, handle, owner, spec, authorize);
    } finally {
      await client.closeHandle(handle, true);
    }
    await directory(client, root, owner);
    await directory(client, dir, owner);
    const staged = attributes(client, await client.lstat(stage));
    privateNode(staged, owner, SSH_S_IFREG | 0o600);
    requireFile(staged.size === spec.size && status(await client.lstat(final)) === SSH_FX_NO_SUCH_FILE, "Managed file already exists or changed.");
    await authorize();
    let result;
    try {
      result = status(await client.rename(stage, final));
    } catch {
      // Losing the acknowledgement after sending RENAME leaves the remote outcome unknown.
      throw new McpFileCommitUnknownError();
    }
    requireFile(result === SSH_FX_OK, "Managed file commit was refused.");
  } catch (error) {
    if (error instanceof McpFileCommitUnknownError) throw error;
    // A disconnect may leave a private, unpublished staging file. Never remove a published file.
    try {
      await directory(client, root, owner);
      await directory(client, dir, owner);
      if (ownsStage) await client.removeFile(stage);
      await client.rmdir(dir);
    } catch { /* leave inaccessible staging data for the SSH account owner */ }
    throw error;
  }
}

export async function downloadMcpFile(client: SFTPClient, spec: McpFileSpec, authorize: Authorize): Promise<Uint8Array<ArrayBuffer>> {
  validate(spec);
  await authorize();
  const owner = await workspace(client, false);
  const dir = root + "/" + spec.fileId;
  await directory(client, dir, owner);
  const path = dir + "/content";
  const file = attributes(client, await client.lstat(path));
  privateNode(file, owner, SSH_S_IFREG | 0o600);
  requireFile(file.size === spec.size, "Unexpected SFTP file size.");
  const handle = extractHandle(await client.openFile(path, SSH_FXF_READ));
  let bytes;
  try {
    bytes = await readVerified(client, handle, owner, spec, authorize);
  } finally {
    await client.closeHandle(handle, true);
  }
  await authorize();
  return bytes;
}

/** Internal cleanup after a recorded physical version is retired; never exposed as an MCP operation. */
export async function removeMcpFile(client: SFTPClient, spec: McpFileSpec, authorize: Authorize): Promise<void> {
  validate(spec);
  await authorize();
  const missing = (packet: Uint8Array) => packet[0] === SSH_FXP_STATUS && status(packet) === SSH_FX_NO_SUCH_FILE;
  if (missing(await client.lstat(root))) return;
  const owner = await workspace(client, false);
  const dir = root + "/" + spec.fileId;
  const directoryNode = await client.lstat(dir);
  if (missing(directoryNode)) return;
  privateNode(attributes(client, directoryNode), owner, SSH_S_IFDIR | 0o700);
  const path = dir + "/content";
  const file = await client.lstat(path);
  if (missing(file)) return;
  privateNode(attributes(client, file), owner, SSH_S_IFREG | 0o600);
  // Cleanup may outlive the D1 mapping. Confirm this is still the exact retired object.
  await downloadMcpFile(client, spec, authorize);
  await directory(client, root, owner);
  await directory(client, dir, owner);
  privateNode(attributes(client, await client.lstat(path)), owner, SSH_S_IFREG | 0o600);
  await authorize();
  ok(await client.removeFile(path));
  await authorize();
  ok(await client.rmdir(dir));
}
