import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { localWorker } from "./helpers/local-worker.mjs";

const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const peerPlugin = {
  name: "rolling-job-peer",
  setup(build) {
    build.onResolve({ filter: /^\.\.\/lib\/mcp-ssh$/ }, ({ importer }) =>
      importer.endsWith("/do/mcp-command-job.ts")
        ? { path: fileURLToPath(new URL("./helpers/rolling-job-peer.mjs", import.meta.url)) } : undefined);
  },
};

async function connect(address, token) {
  let id = 0;
  function post(message) {
    return fetch(new URL("/mcp", address), {
      method: "POST", signal: AbortSignal.timeout(15000),
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json",
        Accept: "application/json, text/event-stream", Connection: "close" },
      body: JSON.stringify({ jsonrpc: "2.0", ...message }),
    });
  }
  async function rpc(method, params) {
    const response = await post({ id: ++id, method, params });
    assert.equal(response.status, 200);
    const envelope = await response.json();
    assert.equal(envelope.id, id);
    assert.ok(!envelope.error);
    return envelope.result;
  }
  await rpc("initialize", { protocolVersion: "2025-11-25", capabilities: {},
    clientInfo: { name: "job-transport-fixture", version: "1" } });
  assert.equal((await post({ method: "notifications/initialized" })).status, 202);
  return async (name, args) => {
    const result = await rpc("tools/call", { name, arguments: args });
    assert.ok(!result.isError);
    return JSON.parse(result.content[0].text);
  };
}

async function verifyReconnect(t, mode) {
  const stdout = Buffer.from("begin\n" + Array.from({ length: 14000 }, (_, i) =>
    String(i).padStart(5, "0") + " 测试数据\n").join("") + "end");
  const stderr = Buffer.from("末尾错误-" + randomUUID());
  const lateStdout = Buffer.from("late stdout " + "x".repeat(64));
  // Split the first multibyte character between peer writes.
  const split = stdout.indexOf(Buffer.from("测")) + 1;
  const next = Promise.withResolvers();
  const finish = Promise.withResolvers();
  let executions = 0;
  const { address, db, request } = await localWorker(t, {
    host: "127.0.0.1", port: 0,
    durableObjects: { SSH_SESSION: { className: "SshSession", useSQLite: true } },
    async outboundService(req) {
      if (req.url === "https://peer.invalid/first") {
        executions++;
        return new Response(stdout.subarray(0, split));
      }
      if (req.url === "https://peer.invalid/next") {
        await next.promise;
        return new Response(stdout.subarray(split));
      }
      if (req.url === "https://peer.invalid/error") return new Response(stderr);
      if (req.url === "https://peer.invalid/last") {
        await finish.promise;
        return new Response(lateStdout);
      }
      return new Response(null, { status: 403 });
    },
  }, [peerPlugin]);
  t.after(next.resolve);
  t.after(finish.resolve);
  const password = randomUUID();
  const web = { Origin: "https://ternssh.example", "Content-Type": "application/json",
    Authorization: "Basic " + Buffer.from("owner:" + password).toString("base64") };
  assert.equal((await request("/api/v1/onboarding/setup", "POST", web,
    { username: "owner", password, confirmPassword: password })).status, 201);
  await db.prepare("INSERT INTO credentials (id,user_id,value) VALUES ('c','default','fixture')").run();
  await db.prepare("INSERT INTO servers (id,user_id,name,host,username,auth_type,credential_ref) VALUES ('s','default','S','s.invalid','fixture','password','c')").run();
  const path = "/api/v1/mcp-access";
  const state = await (await request(path + "/state", "GET", web)).json();
  const { id: serverId, identityVersion } = state.availableServers[0];
  assert.equal((await request(path + "/authorization", "PUT", web, { revision: state.revision,
    servers: [{ id: serverId, identityVersion, ...(mode === "workspace" ? { workspaceShell: true } : {}) }] })).status, 200);
  const { token } = await (await request(path + "/tokens", "POST", web, {})).json();
  const job = { serverId, jobId: randomUUID() };
  const toolName = mode === "workspace" ? "run_workspace_command" : "run_diagnostic";
  const args = mode === "workspace" ? { command: "printf '%s' 'synthetic 中文'" } : { diagnostic: "utc", asJob: true };
  const start = { serverId, ...args, timeoutMs: 90000, requestId: job.jobId };
  const firstClient = await connect(address, token);
  assert.equal((await firstClient(toolName, start)).jobId, job.jobId);
  const read = (client, cursor, limit = 3709) => client("read_job_output", { ...job, cursor, limit });
  async function until(get, predicate) {
    const deadline = Date.now() + 15000;
    let value = await get();
    while (!predicate(value) && Date.now() < deadline) {
      await delay(100);
      value = await get();
    }
    assert.ok(predicate(value), "Timed out waiting for job output");
    return value;
  }
  try {
    const first = await until(() => read(firstClient, 0), page => page.nextCursor === split);
    assert.ok(first.running);
    assert.equal(first.hasMore, false);
    assert.equal((await read(firstClient, split)).frames.length, 0);
    const empty = await firstClient("read_job_tail", { ...job, stream: "stderr" });
    assert.deepEqual(empty.streamTail, { stream: "stderr", startOffset: 0, endOffset: 0, segments: [], missingRanges: [] });
    assert.equal(empty.nextCursor, split);
    assert.ok(empty.running);
    // Every response closes its TCP connection. No client polls or holds a stream here.
    await delay(31000);
    const resumed = await connect(address, token);
    assert.deepEqual(await read(resumed, 0), first);
    assert.ok((await resumed(toolName, start)).running);
    next.resolve();
    const errorTail = () => resumed("read_job_tail", { ...job, stream: "stderr", limit: stderr.length });
    const beforeLast = await until(errorTail, page => page.stderrBytes === stderr.length);
    assert.ok(beforeLast.running);
    assert.equal(beforeLast.hasMore, false);
    assert.equal(beforeLast.nextCursor, stdout.length + stderr.length);
    finish.resolve();
    const terminal = await until(() => resumed("get_job_status", job), state => !state.running);
    assert.equal(terminal.exitCode, 23);
    assert.equal(terminal.outputState, "complete");
    assert.equal(terminal.stdoutBytes, stdout.length + lateStdout.length);
    assert.equal(terminal.stderrBytes, stderr.length);
    assert.deepEqual(terminal.missingRanges, []);
    for (const cursor of [16383, 16384, 16385]) {
      const boundary = await read(resumed, cursor, 1);
      assert.equal(boundary.nextCursor, cursor + 1);
      assert.equal(boundary.frames[0].base64, stdout.subarray(cursor, cursor + 1).toString("base64"));
    }
    const suffix = await read(resumed, beforeLast.nextCursor);
    assert.deepEqual(Buffer.concat(suffix.frames.map(f => Buffer.from(f.base64, "base64"))), lateStdout);
    const tail = await resumed("read_job_tail", { ...job, limit: stderr.length });
    assert.equal(tail.frames.map(frame => frame.text).join(""), lateStdout.subarray(-stderr.length).toString());
    const filtered = await errorTail();
    assert.deepEqual(filtered.streamTail, beforeLast.streamTail);
    assert.equal(filtered.streamTail.stream, "stderr");
    assert.equal(filtered.streamTail.startOffset, 0);
    assert.equal(filtered.streamTail.endOffset, stderr.length);
    assert.deepEqual(filtered.streamTail.missingRanges, []);
    assert.equal(filtered.streamTail.segments[0].offset, 0);
    assert.deepEqual(Buffer.concat(filtered.streamTail.segments.map(s => Buffer.from(s.base64, "base64"))), stderr);
    assert.equal(filtered.streamTail.segments.map(s => s.text).join(""), stderr.toString());
    assert.equal(filtered.nextCursor, terminal.observedBytes);
    const stdoutTail = await resumed("read_job_tail", { ...job, stream: "stdout", limit: lateStdout.length });
    assert.equal(stdoutTail.streamTail.startOffset, stdout.length);
    assert.equal(stdoutTail.streamTail.endOffset, terminal.stdoutBytes);
    assert.equal(stdoutTail.streamTail.segments.map(s => s.text).join(""), lateStdout.toString());
    const parts = { stdout: [], stderr: [] };
    let offset = 0, page = first;
    while (true) {
      for (const frame of page.frames) {
        assert.equal(frame.offset, offset);
        const bytes = Buffer.from(frame.base64, "base64");
        offset += bytes.length;
        parts[frame.stream].push(bytes);
      }
      assert.equal(page.nextCursor, offset);
      if (!page.running && !page.hasMore) break;
      page = await read(resumed, offset);
    }
    assert.ok(stdout.length >= 256 * 1024);
    assert.equal(offset, stdout.length + stderr.length + lateStdout.length);
    assert.equal(sha(Buffer.concat(parts.stdout)), sha(Buffer.concat([stdout, lateStdout])));
    assert.equal(sha(Buffer.concat(parts.stderr)), sha(stderr));
    assert.equal(executions, 1);
  } finally {
    next.resolve();
    finish.resolve();
  }
}

for (const mode of ["diagnostic", "workspace"]) {
  test(`HTTP clients resume a growing ${mode} job after a 30-second disconnect`, { timeout: 100000 },
    t => verifyReconnect(t, mode));
}
