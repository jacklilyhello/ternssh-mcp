import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { SFTPClient } from "../src/ssh/sftp.ts";
import { downloadMcpFile, MCP_FILE_MAX_BYTES, McpFileCommitUnknownError, removeMcpFile, uploadMcpFile } from "../src/lib/mcp-files.ts";

const binary = ["/usr/libexec/sftp-server", "/usr/lib/openssh/sftp-server", "/usr/lib/ssh/sftp-server"].find(existsSync);
const allowed = async () => {};
const specFor = bytes => ({ fileId: randomUUID(), size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
const remoteFile = (home, spec) => join(home, ".ternssh-mcp-files", spec.fileId, "content");

async function openSftp(t, existingHome) {
  assert.ok(binary, "Install OpenSSH sftp-server to run the SFTP regression tests.");
  const home = existingHome || await mkdtemp(join(tmpdir(), "ternssh-sftp-"));
  const child = spawn(binary, ["-d", home], { cwd: home, stdio: ["pipe", "pipe", "ignore"] });
  const closed = once(child, "close");
  const client = new SFTPClient(128 * 1024);
  child.stdin.on("error", () => client.dispose());
  child.once("close", () => client.dispose());
  client.setSendCallback(data => { child.stdin.write(data); });
  child.stdout.on("data", packet => {
    client.feed(packet);
    client.processReceivedPackets();
  });
  t.after(async () => {
    child.stdin.end();
    await closed;
    if (!existingHome) await rm(home, { recursive: true, force: true });
  });
  const version = client.waitForVersion();
  child.stdin.write(client.buildInit());
  assert.equal(await version, 3);
  return { client, home };
}

test("OpenSSH SFTP publishes verified binary, UTF-8 and empty objects and cleans only the retired version", async t => {
  const { client, home } = await openSftp(t);
  const reader = (await openSftp(t, home)).client;
  for (const bytes of [new Uint8Array(140_000).map((_, i) => i % 256), new TextEncoder().encode("换行\n📁"), new Uint8Array()]) {
    const spec = specFor(bytes);
    await uploadMcpFile(client, spec, bytes, allowed);
    assert.deepEqual(await downloadMcpFile(reader, spec, allowed), bytes);
    const file = remoteFile(home, spec);
    assert.equal((await lstat(file)).mode & 0o7777, 0o600);
    assert.equal((await lstat(join(file, ".."))).mode & 0o7777, 0o700);
    await assert.rejects(uploadMcpFile(client, spec, bytes, allowed));
    assert.deepEqual(await readFile(file), Buffer.from(bytes));
    await removeMcpFile(reader, spec, allowed);
    await removeMcpFile(reader, spec, allowed);
    assert.equal(existsSync(file), false);
  }
});

test("concurrent uploads of one physical ID have one winner", async t => {
  const { client, home } = await openSftp(t);
  const second = (await openSftp(t, home)).client;
  const firstBody = Buffer.from("first");
  const secondBody = Buffer.from("other");
  const first = specFor(firstBody);
  const other = { ...specFor(secondBody), fileId: first.fileId };
  const results = await Promise.allSettled([uploadMcpFile(client, first, firstBody, allowed), uploadMcpFile(second, other, secondBody, allowed)]);
  assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
  const winner = results[0].status === "fulfilled" ? firstBody : secondBody;
  assert.deepEqual(await readFile(remoteFile(home, first)), winner);
});

test("size, digest, path, private directory and symlink guards reject before disclosure or deletion", async t => {
  const { client, home } = await openSftp(t);
  const bytes = Buffer.from("same-size");
  const spec = specFor(bytes);
  await assert.rejects(uploadMcpFile(client, { ...spec, fileId: "../x" }, bytes, allowed));
  await assert.rejects(uploadMcpFile(client, { ...spec, size: MCP_FILE_MAX_BYTES + 1 }, bytes, allowed));
  await assert.rejects(uploadMcpFile(client, { ...spec, sha256: "0".repeat(64) }, bytes, allowed));
  const root = join(home, ".ternssh-mcp-files");
  assert.equal(existsSync(root), false);
  const outside = join(home, "outside");
  await mkdir(outside, { mode: 0o700 });
  await symlink(outside, root);
  await assert.rejects(uploadMcpFile(client, spec, bytes, allowed));
  assert.equal(existsSync(join(outside, spec.fileId)), false);
  await rm(root);
  await uploadMcpFile(client, spec, bytes, allowed);
  const path = remoteFile(home, spec);
  await chmod(path, 0o644);
  await assert.rejects(downloadMcpFile(client, spec, allowed));
  await chmod(path, 0o600);
  await writeFile(path, "different");
  await assert.rejects(downloadMcpFile(client, spec, allowed), /digest/);
  await assert.rejects(removeMcpFile(client, spec, allowed), /digest/);
  assert.equal(existsSync(path), true);
  const outsideFile = join(outside, "untouched");
  await rename(path, outsideFile);
  await writeFile(outsideFile, bytes);
  await symlink(outsideFile, path);
  await assert.rejects(downloadMcpFile(client, spec, allowed));
  await assert.rejects(removeMcpFile(client, spec, allowed));
  assert.deepEqual(await readFile(outsideFile), bytes);
  await chmod(home, 0o777);
  await assert.rejects(uploadMcpFile(client, specFor(bytes), bytes, allowed), /starting directory/);
});

test("revocation before rename or release and interrupted writes preserve the previous object", async t => {
  const { client, home } = await openSftp(t);
  const oldBytes = Buffer.from("existing");
  const original = specFor(oldBytes);
  await uploadMcpFile(client, original, oldBytes, allowed);
  const bytes = new Uint8Array(70_000).fill(123);
  const spec = specFor(bytes);
  const write = client.writeFile.bind(client);
  client.writeFile = async (handle, offset, chunk) => {
    if (offset) throw new Error("interrupted");
    return write(handle, offset, chunk);
  };
  await assert.rejects(uploadMcpFile(client, spec, bytes, allowed), /interrupted/);
  assert.equal(existsSync(remoteFile(home, spec)), false);
  client.writeFile = write;
  const stat = client.lstat.bind(client);
  let finishedStaging = false;
  client.lstat = async path => {
    if (path.endsWith(spec.fileId + "/content")) finishedStaging = true;
    return stat(path);
  };
  await assert.rejects(uploadMcpFile(client, spec, bytes, async () => {
    if (finishedStaging) throw new Error("revoked before commit");
  }), /revoked before commit/);
  assert.equal(existsSync(remoteFile(home, spec)), false);
  assert.deepEqual(await readFile(remoteFile(home, original)), oldBytes);
  let checks = 0;
  await assert.rejects(downloadMcpFile(client, original, async () => {
    if (++checks === 2) throw new Error("revoked before release");
  }), /revoked before release/);
});

test("a lost rename acknowledgement is unknown and is never retried or deleted", async t => {
  const { client, home } = await openSftp(t);
  const bytes = Buffer.from([0, 255]);
  const spec = specFor(bytes);
  const commit = client.rename.bind(client);
  let calls = 0;
  client.rename = async (...args) => {
    calls++;
    await commit(...args);
    throw new Error("lost acknowledgement");
  };
  await assert.rejects(uploadMcpFile(client, spec, bytes, allowed), McpFileCommitUnknownError);
  assert.equal(calls, 1);
  assert.deepEqual(await readFile(remoteFile(home, spec)), bytes);
});

test("retirement rechecks the active grant after verifying bytes and immediately before unlink", async t => {
  const { client, home } = await openSftp(t);
  const bytes = new Uint8Array(200_000).fill(19);
  const spec = specFor(bytes);
  await uploadMcpFile(client, spec, bytes, allowed);
  const stat = client.lstat.bind(client);
  let pathChecks = 0;
  client.lstat = async path => {
    if (path.endsWith("/content")) pathChecks++;
    return stat(path);
  };
  let calls = 0;
  await assert.rejects(removeMcpFile(client, spec, async () => {
    calls++;
    if (pathChecks >= 3) throw new Error("ended before deletion");
  }), /ended before deletion/);
  assert.ok(calls >= 4);
  assert.deepEqual(await readFile(remoteFile(home, spec)), Buffer.from(bytes));
});

test("managed SFTP rejects oversized declared or accumulated packet data", () => {
  const client = new SFTPClient(128 * 1024);
  client.feed(Uint8Array.of(0x7f, 0xff, 0xff, 0xff));
  assert.throws(() => client.processReceivedPackets(), /length/);
  assert.throws(() => client.feed(new Uint8Array(128 * 1024 + 1)), /limit/);
});
