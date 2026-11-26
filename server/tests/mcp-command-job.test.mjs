import assert from "node:assert/strict";
import test from "node:test";
import { McpCommandJob } from "../src/do/mcp-command-job.ts";
import { issueMcpToken, replaceMcpAuthorization } from "../src/db/mcp-access.ts";
import { checkWorkspaceLease, reserveWorkspaceRequest } from "../src/db/mcp-workspace-leases.ts";
import { workspaceShellCommand } from "../src/lib/mcp-workspace.ts";
import { ExecCompletionError } from "../src/ssh/session.ts";
import { jobStorage } from "./helpers/job-storage.mjs";
import { localWorker } from "./helpers/local-worker.mjs";

function fixture(t, config = {}) {
  const jobId = crypto.randomUUID();
  const target = config.target ?? { userId: "owner", serverId: "server", tokenId: "client", revision: 2, identityVersion: "version" };
  let authorized = true;
  const audit = [];
  const env = {
    DB: config.db ?? {
      withSession: () => ({ prepare: () => ({ bind: () => ({ first: () => authorized ? { valid: 1 } : null }) }) }),
      prepare: () => ({ bind: (outcome) => ({ run: async () => { audit.push(outcome); } }) }),
    },
    SSH_SESSION: { idFromName: name => name },
  };
  const entries = new Map();
  const storage = Object.assign(jobStorage(t), {
    kv: {
      get: key => structuredClone(entries.get(key)),
      put: (key, value) => entries.set(key, structuredClone(value)),
      delete: key => entries.delete(key),
    },
    async sync() {}, async setAlarm() {},
  });
  const ctx = { storage, id: { equals: name => name === `mcp-job:${target.tokenId}:${jobId}` } };
  const started = Promise.withResolvers();
  const finish = Promise.withResolvers();
  let commands = 0;
  const session = {
    async execCommand(command, _timeout, check, _limit, append) {
      await check();
      commands++;
      append("stdout", Uint8Array.of(65));
      started.resolve({ command, append });
      return finish.promise;
    },
    async requestExecTermination() {
      finish.reject(new ExecCompletionError("terminated", "", "", null, "TERM", false, false, true));
    },
    close() {},
  };
  const make = () => new McpCommandJob(ctx, env, async (_db, _target, check) => {
    if (config.authenticate) await config.authenticate(check);
    return session;
  });
  const service = make();
  const call = async (path, args = {}, receiver = service) => {
    const response = await receiver.fetch(new Request(`https://mcp-job.internal/${path}`, {
      method: "POST", body: JSON.stringify({ target, jobId, ...args }),
    }));
    return { code: response.status, data: await response.json() };
  };
  return { service, call, started: started.promise, finish, make, entries, audit, jobId, commands: () => commands,
    target, revoke: () => { authorized = false; } };
}

test("workspace jobs bind a single dispatch to grant, exact input, timeout and an active lease", async t => {
  const { db } = await localWorker(t);
  const serverId = "workspace-fixture", userId = "default";
  await db.prepare("INSERT INTO credentials(id,user_id,value) VALUES ('fixture-credential',?,'synthetic')").bind(userId).run();
  await db.prepare(`INSERT INTO servers(id,user_id,name,host,username,auth_type,credential_ref)
    VALUES (?,?,'Fixture','fixture.invalid','fixture','password','fixture-credential')`).bind(serverId,userId).run();
  const identityVersion = await db.prepare("SELECT version FROM mcp_target_identities WHERE server_id=?")
    .bind(serverId).first("version");
  const selection = { id: serverId, identityVersion, workspaceShell: true };
  await replaceMcpAuthorization(db, userId, 0, [selection]);
  const target = { userId, serverId, revision: 1, identityVersion, tokenId: (await issueMcpToken(db,userId)).id };
  const submit = { command: "printf '%s' 'fixture | 中文' ", timeoutMs: 30000 };
  const f = fixture(t, { target, db, authenticate: check => check() });
  assert.equal((await f.call("workspace-reconcile", submit)).code, 404);
  assert.equal((await f.call("workspace-start", submit)).code, 410);
  assert.equal(f.entries.size, 0);
  assert.equal(await reserveWorkspaceRequest(db, target, f.jobId, submit.timeoutMs), "workspace-start");
  const pair = await Promise.all([f.call("workspace-start", submit), f.call("workspace-start", submit)]);
  assert.ok(pair.every(r => r.data.environment === "isolated_workspace" && r.data.status === "queued"));
  assert.equal((await f.call("workspace-reconcile", { ...submit, command: submit.command.trim() })).code, 409);
  assert.equal((await f.call("workspace-reconcile", { ...submit, timeoutMs: 2000 })).code, 409);
  assert.equal((await f.call("start", { diagnostic: "utc" })).code, 409);
  assert.equal((await f.call("workspace-start", { ...submit, diagnostic: "utc" })).code, 400);
  const alarm = f.service.alarm();
  const sent = await f.started;
  assert.ok(sent.command !== submit.command && sent.command === workspaceShellCommand(submit.command, submit.timeoutMs));
  const first = (await f.call("read")).data;
  assert.equal(first.running, true);
  assert.equal(first.nextCursor, 1);
  sent.append("stderr", Uint8Array.of(66));
  f.finish.resolve({ exitCode: 23 });
  await alarm;
  const terminal = (await f.call("workspace-reconcile", submit)).data;
  assert.equal(terminal.status, "failed");
  assert.equal(terminal.exitCode, 23);
  assert.equal((await f.call("tail", { limit: 1 })).data.frames[0].stream, "stderr");
  assert.equal((await f.call("read", { cursor: 1 })).data.frames[0].text, "B");
  const persisted = f.entries.get("mcp-command-job").workspace;
  assert.deepEqual(Object.keys(persisted), ["digest"]);
  assert.match(persisted.digest, /^[0-9a-f]{64}$/);
  assert.equal(await reserveWorkspaceRequest(db, target, f.jobId, submit.timeoutMs), "workspace-reconcile");
  await assert.rejects(checkWorkspaceLease(db, target, f.jobId, submit.timeoutMs), e => e.status === 410);
  assert.equal(f.commands(), 1);

  const unknown = fixture(t, { target, db });
  await reserveWorkspaceRequest(db, target, unknown.jobId, submit.timeoutMs);
  await unknown.call("workspace-start", submit);
  const interrupted = unknown.service.alarm();
  await unknown.started;
  unknown.finish.reject(new ExecCompletionError("synthetic peer closed", "", "", null, null));
  await interrupted;
  assert.equal((await unknown.call("status")).data.status, "unknown");
  assert.equal(unknown.entries.get("mcp-command-job").workspace.command, undefined);
  await checkWorkspaceLease(db, target, unknown.jobId, submit.timeoutMs);

  // Remove just workspace permission while leaving the general host selected.
  // This distinguishes the workspace guard from a generic host allowlist check.
  const narrow = () => db.prepare("UPDATE mcp_authorizations SET selection=json_remove(selection,'$[0].workspaceShell') WHERE user_id=?")
    .bind(userId).run();
  const denied = fixture(t, { target, db, async authenticate(check) { await narrow(); await check(); } });
  await reserveWorkspaceRequest(db, target, denied.jobId, submit.timeoutMs);
  await denied.call("workspace-start", submit);
  await denied.service.alarm();
  const stopped = denied.entries.get("mcp-command-job");
  assert.equal(stopped.dispatched, false);
  assert.equal(stopped.workspace.command, undefined);
  assert.equal(denied.commands(), 0);
  for (const action of ["status","cancel","read","tail"]) assert.equal((await f.call(action)).code, 403);
  assert.equal((await f.call("workspace-reconcile", submit)).code, 403);
  const legacy = fixture(t, { target, db });
  assert.equal((await legacy.call("start", { diagnostic: "utc" })).code, 200);
  assert.equal((await legacy.call("workspace-start", submit)).code, 403);
  await replaceMcpAuthorization(db, userId, 1, [selection]);
  assert.equal((await legacy.call("workspace-reconcile", { ...submit, target: { ...target, revision: 2 } })).code, 404);
});

test("duplicate submission and lost receipt dispatch once; independent polls see new output and the exit code", async t => {
  const f = fixture(t);
  const submit = { diagnostic: "utc", timeoutMs: 30000 };
  assert.equal((await f.call("reconcile", submit)).code, 404);
  assert.equal(f.commands(), 0);
  assert.equal((await f.call("start", { command: "uptime" })).code, 400);
  assert.equal((await f.call("start", { ...submit, command: "uptime" })).code, 400);
  const queued = await Promise.all([f.call("start", submit), f.call("start", submit)]);
  assert.ok(queued.every(r => r.data.status === "queued"));
  const alarm = f.service.alarm();
  const { command, append } = await f.started;
  assert.equal(command, "/bin/date -u '+%Y-%m-%dT%H:%M:%SZ'");
  const page = (await f.call("read")).data;
  assert.equal(page.running, true);
  assert.equal(page.frames[0].text, "A");
  assert.equal((await f.call("read", { cursor: page.nextCursor })).data.frames.length, 0);
  assert.equal((await f.call("start", submit)).data.running, true);
  assert.equal((await f.call("reconcile", submit)).data.running, true);
  assert.equal((await f.call("reconcile", { ...submit, timeoutMs: 2000 })).code, 409);
  assert.equal((await f.call("start", { ...submit, diagnostic: "system_name" })).code, 409);
  append("stderr", Uint8Array.of(66));
  f.finish.resolve({ exitCode: 47 });
  await alarm;
  const [read, retry, tail] = await Promise.all([
    f.call("read", { cursor: page.nextCursor }), f.call("read", { cursor: page.nextCursor }), f.call("tail", { limit: 1 }),
  ]);
  assert.deepEqual(read.data, retry.data);
  assert.equal(tail.data.frames[0].text, "B");
  assert.equal(read.data.exitCode, 47);
  assert.equal(read.data.running, false);
  assert.equal(read.data.outputState, "complete");
  await f.service.alarm();
  assert.equal(f.commands(), 1);
  assert.deepEqual(f.audit, ["failed"]);
  assert.equal((await f.call("read", { target: { ...f.target, revision: 3 } })).code, 404);
  f.revoke();
  for (const action of ["read", "tail", "status", "cancel"]) assert.equal((await f.call(action)).code, 403);
});

test("expiry clears output and a delayed duplicate cannot execute", async t => {
  const f = fixture(t);
  const submit = { diagnostic: "utc" };
  await f.call("start", submit);
  const alarm = f.service.alarm();
  await f.started;
  f.finish.resolve({ exitCode: 0 });
  await alarm;
  const job = f.entries.get("mcp-command-job");
  job.expiresAt = Date.now() - 1;
  const expired = await f.call("tail");
  assert.equal(expired.code, 410);
  assert.deepEqual(expired.data.missingRanges, [{ start: 0, end: 1 }]);
  assert.equal((await f.call("start", submit)).code, 410);
  assert.equal(f.commands(), 1);
});

test("cancel before dispatch prevents all network work, after dispatch it preserves an observed signal", async t => {
  const queued = fixture(t);
  await queued.call("start", { diagnostic: "utc" });
  assert.equal((await queued.call("cancel")).data.status, "cancelled");
  await queued.service.alarm();
  assert.equal(queued.commands(), 0);

  const live = fixture(t);
  await live.call("start", { diagnostic: "utc" });
  const alarm = live.service.alarm();
  await live.started;
  await live.call("cancel");
  await alarm;
  const status = (await live.call("status")).data;
  assert.equal(status.status, "cancelled");
  assert.equal(status.signal, "TERM");
  assert.equal(status.exitCode, null);
  assert.equal(status.outputState, "complete");
});

test("connection loss and alarm redelivery after restart cannot replay a dispatched job", async t => {
  const f = fixture(t);
  await f.call("start", { diagnostic: "utc" });
  const alarm = f.service.alarm();
  await f.started;
  f.finish.reject(new ExecCompletionError("connection interrupted", "", "", null, null));
  await alarm;
  assert.equal((await f.call("status")).data.status, "unknown");
  // Restore the durable send boundary as it stood before terminal metadata was published.
  Object.assign(f.entries.get("mcp-command-job"), { status: "running", expiresAt: null, reason: null });
  const restored = f.make();
  await restored.alarm();
  const page = (await f.call("read", {}, restored)).data;
  assert.equal(page.status, "unknown");
  assert.equal(page.reason, "executor_restarted");
  assert.equal(page.unknownSuffixFrom, 1);
  assert.equal(page.frames[0].text, "A");
  assert.equal(f.commands(), 1);
});

test("the deadline covers queued time and a live diagnostic, including its confirmed remote signal", async t => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"] });
  const queued = fixture(t);
  const args = { diagnostic: "utc", timeoutMs: 1000 };
  await queued.call("start", args);
  t.mock.timers.tick(1001);
  await queued.service.alarm();
  const before = (await queued.call("status")).data;
  assert.equal(before.status, "timeout");
  assert.equal(before.dispatched, false);
  assert.equal(queued.commands(), 0);

  const live = fixture(t);
  await live.call("start", args);
  const alarm = live.service.alarm();
  await live.started;
  t.mock.timers.tick(1000);
  await alarm;
  const after = (await live.call("status")).data;
  assert.equal(after.status, "timeout");
  assert.equal(after.reason, "timeout");
  assert.equal(after.signal, "TERM");
  assert.equal(after.resultKnown, true);
  assert.equal(live.commands(), 1);
});

test("orderly channel closure can prove the output is complete independently of a missing exit status", async t => {
  const f = fixture(t);
  await f.call("start", { diagnostic: "utc" });
  const alarm = f.service.alarm();
  await f.started;
  f.finish.reject(new ExecCompletionError("no status", "", "", null, null, false, false, true));
  await alarm;
  const { data } = await f.call("tail");
  assert.equal(data.status, "unknown");
  assert.equal(data.reason, "no_exit_status");
  assert.equal(data.resultKnown, false);
  assert.equal(data.outputState, "complete");
  assert.equal(data.unknownSuffixFrom, null);
  assert.equal(data.frames[0].text, "A");
});
