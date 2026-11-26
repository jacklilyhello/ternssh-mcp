import assert from "node:assert/strict";
import test from "node:test";
import { issueMcpToken, replaceMcpAuthorization } from "../src/db/mcp-access.ts";
import { acceptSignedBatch, describeApproval, registerApprovalKey } from "../src/db/mcp-batch-approvals.ts";
import { prepareCommandBatch } from "../src/db/mcp-command-batches.ts";
import { McpBatchRunner } from "../src/do/mcp-batch-runner.ts";
import { McpCommandJob } from "../src/do/mcp-command-job.ts";
import { jobStorage } from "./helpers/job-storage.mjs";
import { localWorker } from "./helpers/local-worker.mjs";

test("a lost handoff reply reconciles one approved child; approval and queue position guard the SSH boundary", async t => {
  // Real migrated D1, real signature verification. The ephemeral test key and
  // synthetic peer are scoped to the test process and never enter the Worker.
  const { db } = await localWorker(t);
  const userId = "default", serverId = "batch-fixture";
  await db.prepare("INSERT INTO credentials(id,user_id,value) VALUES ('test-key',?,'fixture')").bind(userId).run();
  await db.prepare(`INSERT INTO servers(id,user_id,name,host,username,auth_type,credential_ref)
    VALUES (?,?,'Fixture','fixture.invalid','fixture','password','test-key')`).bind(serverId, userId).run();
  const identityVersion = await db.prepare("SELECT version FROM mcp_target_identities WHERE server_id=?")
    .bind(serverId).first("version");
  await replaceMcpAuthorization(db, userId, 0, [{ id: serverId, identityVersion }]);
  const target = { userId, serverId, revision: 1, identityVersion, tokenId: (await issueMcpToken(db, userId)).id };
  const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const b64 = data => Buffer.from(data).toString("base64");
  const spki = await crypto.subtle.exportKey("spki", key.publicKey);
  const fingerprint = Buffer.from(await crypto.subtle.digest("SHA-256", spki)).toString("hex");
  await registerApprovalKey(db, userId, target.tokenId, b64(spki), fingerprint);
  const input = { batchId: crypto.randomUUID(), commands: ["fixture one", "fixture two"], timeoutMs: 20000 };
  const proposal = await prepareCommandBatch(db, target, input);
  const origin = "https://ternssh.example";
  const details = await describeApproval(db, origin, target, proposal, fingerprint);
  const args = { target, batchId: input.batchId, digest: proposal.digest };
  const batchName = `mcp-batch:${target.tokenId}:${input.batchId}`;
  const actors = new Map();
  let handoffs = 0, connections = 0, dropReply = false;
  const commands = [];
  const env = { DB: db, TERNSSH_APPROVER_SHA256: fingerprint, SSH_SESSION: {
    idFromName: name => name,
    get(name) {
      return { fetch: async (url, init) => {
        const response = await actor(name).fetch(new Request(url, init));
        if (url === "https://mcp-job.internal/batch-item" && response.ok) {
          handoffs++;
          if (dropReply) { dropReply = false; throw new Error("Lost synthetic reply"); }
        }
        return response;
      } };
    },
  } };
  function actor(name) {
    if (!actors.has(name)) {
      const values = new Map();
      const ctx = { id: { equals: other => name === other }, storage: Object.assign(jobStorage(t), {
        kv: { get: k => structuredClone(values.get(k)), put: (k,v) => values.set(k, structuredClone(v)) },
        setAlarm: async () => {}, sync: async () => {},
      }) };
      const peer = async (_db, _target, recheck) => {
        connections++;
        await recheck();
        return { close() {}, async execCommand(command, _timeout, beforeSend, _limit, output) {
          await beforeSend();
          commands.push(command);
          output("stdout", Uint8Array.of(65));
          return { stdout: "", stderr: "", exitCode: 0 };
        } };
      };
      actors.set(name, name.startsWith("mcp-batch:") ? new McpBatchRunner(ctx, env) : new McpCommandJob(ctx, env, peer));
    }
    return actors.get(name);
  }
  const batch = actor(batchName);
  const post = (host, action, body) => new Request(`https://${host}.internal/${action}`,
    { method: "POST", body: JSON.stringify(body) });
  const call = (action, extra = {}) => batch.fetch(post("mcp-batch", action, { ...args, ...extra }));
  assert.equal((await call("start")).status, 403);
  const signature = b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey,
    Buffer.from(details.approvalPayloadBase64, "base64")));
  await acceptSignedBatch(db, origin, target, args.batchId, args.digest, signature, fingerprint);
  // Simulate interruption after the D1 consume and before the first coordinator
  // message arrives. A status lookup never generates children or resumes a start.
  assert.equal((await call("status", { digest: "f".repeat(64) })).status, 404);
  for (let attempt = 0; attempt < 2; attempt++) {
    const missing = await (await call("status")).json();
    assert.equal(missing.status, "unknown");
    assert.equal(missing.running, null);
    assert.deepEqual(missing.items, []);
  }
  assert.equal(handoffs, 0);
  delete env.TERNSSH_APPROVER_SHA256;
  assert.equal((await call("start")).status, 403);
  env.TERNSSH_APPROVER_SHA256 = fingerprint;
  assert.equal((await call("start", { commands: ["unapproved"] })).status, 400);
  const [first, second] = await Promise.all([call("start"), call("start")]);
  const receipt = await first.json();
  assert.deepEqual((await second.json()).items, receipt.items);
  const children = receipt.items.map(({ jobId }) => actor(`mcp-job:${target.tokenId}:${jobId}`));
  const itemArgs = (index) => ({ ...args, index, jobId: receipt.items[index].jobId });
  assert.equal((await children[1].fetch(post("mcp-job", "batch-item", itemArgs(1)))).status, 403);
  assert.equal((await children[0].fetch(post("mcp-job", "batch-item",
    { ...itemArgs(0), command: "substitution" }))).status, 400);
  assert.deepEqual(commands, []);
  dropReply = true;
  await batch.alarm();
  await batch.alarm();
  assert.equal(handoffs, 1);
  await children[0].alarm();
  await batch.alarm();
  assert.deepEqual(commands, [input.commands[0]]);
  assert.equal(handoffs, 1);
  assert.deepEqual((await (await call("status")).json()).items.map(i => i.status), ["completed", "waiting"]);
  await call("cancel");
  await batch.alarm();
  const stopped = await (await call("status")).json();
  assert.equal(stopped.status, "cancelled");
  assert.deepEqual(stopped.items.map(i => i.status), ["completed", "skipped"]);
  assert.equal((await (await call("start")).json()).status, "cancelled");
  assert.equal(await db.prepare("SELECT count(commands) AS n FROM mcp_batch_approvals").first("n"), 0);
  assert.equal(handoffs, 1);

  // A deployment pin can change after the approved job is queued. The child
  // must fail closed before even opening its independent SSH connection.
  const next = await prepareCommandBatch(db, target, { ...input, batchId: crypto.randomUUID() });
  const nextDetails = await describeApproval(db, origin, target, next, fingerprint);
  const nextSignature = b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey,
    Buffer.from(nextDetails.approvalPayloadBase64, "base64")));
  await acceptSignedBatch(db, origin, target, next.batchId, next.digest, nextSignature, fingerprint);
  const nextBatch = actor(`mcp-batch:${target.tokenId}:${next.batchId}`);
  const started = await nextBatch.fetch(post("mcp-batch", "start", { target, batchId: next.batchId, digest: next.digest }));
  const [{ jobId }] = (await started.json()).items;
  await nextBatch.alarm();
  const nextChild = actor(`mcp-job:${target.tokenId}:${jobId}`);
  env.TERNSSH_APPROVER_SHA256 = "0".repeat(64);
  await nextChild.alarm();
  const denied = await (await nextChild.fetch(post("mcp-job", "status", { target, jobId }))).json();
  assert.equal(denied.dispatched, false);
  assert.equal(denied.status, "failed");
  assert.equal(connections, 1);
  assert.deepEqual(commands, [input.commands[0]]);

  env.TERNSSH_APPROVER_SHA256 = fingerprint;
  const orphan = await prepareCommandBatch(db, target, { ...input, batchId: crypto.randomUUID() });
  const preview = await describeApproval(db, origin, target, orphan, fingerprint);
  const orphanArgs = { target, batchId: orphan.batchId, digest: orphan.digest };
  const orphanSignature = b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey,
    Buffer.from(preview.approvalPayloadBase64, "base64")));
  await acceptSignedBatch(db, origin, target, orphan.batchId, orphan.digest, orphanSignature, fingerprint);
  const orphanBatch = actor(`mcp-batch:${target.tokenId}:${orphan.batchId}`);
  const invoke = async action => (await orphanBatch.fetch(post("mcp-batch", action, orphanArgs))).json();
  assert.equal((await invoke("cancel")).status, "unknown");
  assert.deepEqual((await invoke("start")).items, []);
  assert.equal((await invoke("status")).running, false);
  await orphanBatch.alarm();
  assert.deepEqual(commands, [input.commands[0]]);
});
