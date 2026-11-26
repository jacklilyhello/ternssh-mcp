#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, open, rename, unlink } from "node:fs/promises";
import https from "node:https";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";

const limit = 1024 * 1024;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const usage = "node scripts/mcp-transfer.mjs upload|download --operation UUID --file PATH [--origin HTTPS_ORIGIN] [--overwrite]";
const unknownUpload = "The gateway did not confirm the upload. Check the prepared file ID before starting a new transfer.";

class TransferError extends Error {
  constructor(message, status = "failed") {
    super(message);
    this.status = status;
  }
}

function origin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TransferError("Invalid HTTPS origin.");
  }
  if (!/^https:\/\/[^/?#\\\s@]+\/?$/i.test(value) || url.protocol !== "https:" ||
      url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new TransferError("The paired origin must be a bare HTTPS origin without credentials, path, query, or fragment.");
  }
  return url.origin;
}

function inputs() {
  const [direction, ...args] = process.argv.slice(2);
  let values;
  try {
    ({ values } = parseArgs({ args, options: {
      operation: { type: "string" }, file: { type: "string" },
      overwrite: { type: "boolean" }, origin: { type: "string" },
    } }));
  } catch {
    throw new TransferError(usage);
  }
  if (!["upload", "download"].includes(direction) || !uuid.test(values.operation ?? "") ||
      !values.file || (direction === "upload" && values.overwrite)) {
    throw new TransferError(usage);
  }
  const pairedOrigin = process.env.TERNSSH_MCP_ORIGIN;
  if (!pairedOrigin) {
    throw new TransferError("Set TERNSSH_MCP_ORIGIN to the HTTPS origin that issued the pairing token.");
  }
  const pinned = origin(pairedOrigin);
  if (values.origin !== undefined && origin(values.origin) !== pinned) {
    throw new TransferError("The requested origin does not match TERNSSH_MCP_ORIGIN for this pairing.");
  }
  const token = process.env.TERNSSH_MCP_TOKEN;
  if (!/^tmcp_[A-Za-z0-9_-]{43}$/.test(token ?? "")) {
    throw new TransferError("Set TERNSSH_MCP_TOKEN to the dedicated token for the paired origin.");
  }
  return { direction, url: new URL("/api/mcp-transfers/" + values.operation, pinned),
    file: resolve(values.file), overwrite: values.overwrite === true, token };
}

// Cap the actual bytes read as the source can grow after stat().
async function readLocal(handle) {
  const stat = await handle.stat();
  if (!stat.isFile()) throw new TransferError("Expected a regular local file.");
  if (stat.size > limit) throw new TransferError("The local file exceeds 1 MiB.");
  const buffer = Buffer.allocUnsafe(limit + 1);
  let offset = 0;
  while (offset <= limit) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
    if (bytesRead === 0) return buffer.subarray(0, offset);
    offset += bytesRead;
  }
  throw new TransferError("The local file exceeds 1 MiB.");
}

async function request({ url, token, direction }, body) {
  const upload = direction === "upload";
  const headers = { Authorization: "Bearer " + token, "Accept-Encoding": "identity" };
  if (upload) Object.assign(headers, {
    "Content-Type": "application/octet-stream", "Content-Length": body.length,
    "X-Content-SHA256": sha256(body),
  });
  // One HTTPS request. Node's core client does not follow redirects.
  const response = await new Promise((fulfill, reject) => {
    const req = https.request(url, {
      method: upload ? "PUT" : "GET", headers, agent: false,
      rejectUnauthorized: true, signal: AbortSignal.timeout(60_000),
    }, fulfill);
    req.once("error", reject);
    req.end(body);
  }).catch(() => {
    throw new TransferError(upload ? unknownUpload : "Could not reach the paired gateway.", upload ? "unknown" : "failed");
  });

  const code = response.statusCode;
  if (code < 200 || code >= 300) {
    response.destroy();
    const uncertain = upload && (code === 409 || code >= 500 || (code >= 300 && code < 400));
    throw new TransferError(`Transfer gateway returned HTTP ${code}.` + (uncertain ? " " + unknownUpload : ""),
      uncertain ? "unknown" : "failed");
  }

  const max = upload ? 4096 : limit;
  try {
    const encoding = response.headers["content-encoding"];
    const length = response.headers["content-length"];
    if ((encoding && encoding.toLowerCase() !== "identity") ||
        (length !== undefined && (!/^\d+$/.test(length) || Number(length) > max))) {
      throw new TransferError("The gateway returned an invalid or oversized response.");
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response) {
      size += chunk.length;
      if (size > max) throw new TransferError("The gateway response exceeds the transfer limit.");
      chunks.push(chunk);
    }
    if (!response.complete || (length !== undefined && Number(length) !== size)) {
      throw new TransferError("The transfer was interrupted.");
    }
    return { bytes: Buffer.concat(chunks, size), digest: response.headers["x-content-sha256"] };
  } catch (error) {
    if (upload) throw new TransferError(unknownUpload, "unknown");
    throw error instanceof TransferError ? error : new TransferError("The download was interrupted.");
  } finally {
    response.destroy();
  }
}

async function upload(options) {
  const handle = await open(options.file, constants.O_RDONLY | constants.O_NONBLOCK);
  let bytes;
  try {
    bytes = await readLocal(handle);
  } finally {
    await handle.close();
  }
  const response = await request(options, bytes);
  const digest = sha256(bytes);
  let receipt;
  try {
    receipt = JSON.parse(response.bytes.toString("utf8"));
  } catch {
    throw new TransferError(unknownUpload, "unknown");
  }
  if (typeof receipt?.fileId !== "string" || !uuid.test(receipt.fileId) ||
      receipt.bytes !== bytes.length || receipt.sha256 !== digest) {
    throw new TransferError(unknownUpload, "unknown");
  }
  return { status: "uploaded", fileId: receipt.fileId, file: options.file, bytes: bytes.length, sha256: digest };
}

async function download(options) {
  const dest = options.file;
  const existing = await lstat(dest).catch((error) => {
    if (error.code !== "ENOENT") throw error;
    return null;
  });
  if (existing && !options.overwrite) throw new TransferError("The local destination already exists.");
  if (existing && !existing.isFile()) throw new TransferError("Local overwrite requires a regular destination file.");

  // Stage on the destination filesystem, so installation is atomic and a
  // failed download cannot truncate the previous destination.
  const temp = join(dirname(dest), ".ternssh-part-" + randomUUID());
  const handle = await open(temp, "wx+", 0o600);
  let tempExists = true;
  try {
    let bytes, digest;
    try {
      ({ bytes, digest } = await request(options));
      if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest) || sha256(bytes) !== digest) {
        throw new TransferError("The downloaded bytes do not match the gateway SHA-256.");
      }
      await handle.writeFile(bytes);
      await handle.sync();
      if (sha256(await readLocal(handle)) !== digest) throw new TransferError("Staged file verification failed.");
    } finally {
      await handle.close();
    }
    if (options.overwrite) {
      await rename(temp, dest);
      tempExists = false;
    } else {
      // link() fails atomically if another process created dest since lstat().
      await link(temp, dest);
    }
    const installed = await open(dest, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const actual = await readLocal(installed);
      if (actual.length !== bytes.length || sha256(actual) !== digest) {
        throw new TransferError("The installed local file failed verification.");
      }
    } finally {
      await installed.close();
    }
    return { status: "saved", file: dest, bytes: bytes.length, sha256: digest };
  } finally {
    if (tempExists) await unlink(temp);
  }
}

try {
  const options = inputs();
  const result = await (options.direction === "upload" ? upload(options) : download(options));
  console.log(JSON.stringify(result));
} catch (error) {
  const message = error instanceof TransferError ? error.message
    : error.code === "EEXIST" ? "The local destination already exists."
    : "Local file access or verification failed. Check the file path and permissions.";
  console.error(JSON.stringify({ status: error instanceof TransferError ? error.status : "failed", message }));
  process.exitCode = 1;
}
