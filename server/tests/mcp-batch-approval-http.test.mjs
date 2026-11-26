import assert from "node:assert/strict";
import { createHash, randomUUID, webcrypto } from "node:crypto";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { localWorker } from "./helpers/local-worker.mjs";

// Only the CI bundle replaces the job's SSH peer. Authorization, signed
// receipt verification, the batch coordinator, child alarms and storage all
// use the production Worker entry point and a disposable Miniflare database.
const peer = {
  name: "approval-test-peer",
  setup(build) {
    build.onResolve({ filter: /^\.\.\/lib\/mcp-ssh$/ }, ({ importer }) =>
      importer.endsWith("/do/mcp-command-job.ts") ? { path: "peer", namespace: "batch-fixture" } : undefined);
    build.onLoad({ filter: /^peer$/, namespace: "batch-fixture" }, () => ({
      resolveDir: fileURLToPath(new URL("../src/do/", import.meta.url)),
      contents: `
        export { isMcpDiagnostic, fixedDiagnosticCommand, McpSshError } from "../lib/mcp-ssh";
        export async function openPinnedMcpSession() {
          return {
            async execCommand(command, timeout, beforeDispatch, limit, append) {
              await beforeDispatch();
              const response = await fetch("https://approval-peer.invalid/receive", {method: "POST", body: command});
              if (!response.ok) throw new Error("Fixture peer unavailable");
              const result = await response.json();
              append("stdout", new TextEncoder().encode(result.stdout));
              append("stderr", new TextEncoder().encode(result.stderr));
              return { exitCode: result.exitCode };
            },
            close() {},
          };
        }`,
    }));
  },
};

const manager = "/api/v1/mcp-access";
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const alg = { name: "ECDSA", namedCurve: "P-256" };

async function fixtureKey() {
  const { privateKey, publicKey } = await webcrypto.subtle.generateKey(alg, false, ["sign", "verify"]);
  const der = Buffer.from(await webcrypto.subtle.exportKey("spki", publicKey));
  return {
    publicKeySpki: der.toString("base64"), fingerprint: digest(der),
    async sign(bytes) {
      const signature = await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, bytes);
      return Buffer.from(signature).toString("base64");
    },
  };
}

async function setupPairing(db, request) {
  const password = randomUUID();
  const web = { Origin: "https://ternssh.example", "Content-Type": "application/json",
    Authorization: "Basic " + Buffer.from("owner:" + password).toString("base64") };
  assert.equal((await request("/api/v1/onboarding/setup", "POST", web,
    { username: "owner", password, confirmPassword: password })).status, 201);
  await db.prepare("INSERT INTO credentials(id,user_id,value) VALUES ('c','default','synthetic')").run();
  await db.prepare(`INSERT INTO servers(id,user_id,name,host,username,auth_type,credential_ref)
    VALUES ('s','default','Fixture','fixture.invalid','fixture','password','c')`).run();
  const state = await (await request(manager + "/state", "GET", web)).json();
  const { id: serverId, identityVersion } = state.availableServers[0];
  assert.equal((await request(manager + "/authorization", "PUT", web, { revision: state.revision,
    servers: [{ id: serverId, identityVersion }] })).status, 200);
  const pair = async () => (await request(manager + "/tokens", "POST", web, {})).json();
  const enroll = (pairing, publicKeySpki, headers = web) =>
    request(manager + "/tokens/" + pairing.id + "/approval-key", "POST", headers, { publicKeySpki });
  return { web, serverId, pair, enroll };
}

function mcpClient(request, defaultPair) {
  return async function call(tool, args, expected = 200, pairing = defaultPair) {
    const response = await request("/mcp", "POST", { Authorization: "Bearer " + pairing.token,
      "Content-Type": "application/json", Accept: "application/json, text/event-stream" }, {
      jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: args },
    });
    assert.equal(response.status, 200);
    const rpc = await response.json();
    if (expected < 0) { assert.equal(rpc.error?.code, expected); return; }
    assert.ok(rpc.result);
    const value = JSON.parse(rpc.result.content[0].text);
    assert.equal(rpc.result.isError ?? false, expected !== 200);
    if (expected !== 200) assert.equal(value.code, expected);
    return value;
  };
}

test("web-enrolled signatures bind exact ordered proposals and execute each approved item once", { timeout: 90_000 }, async t => {
  const commands = ["printf '%s' 'synthetic | 中文' ", "printf 'fixture error' >&2; exit 37", "printf 'skipped'"];
  const replies = [
    { stdout: "fixture 中文", stderr: "", exitCode: 0 },
    { stdout: "", stderr: "fixture error", exitCode: 37 },
  ];
  const [key, wrong] = await Promise.all([fixtureKey(), fixtureKey()]);
  const received = [];
  const { db, request } = await localWorker(t, {
    bindings: { TERNSSH_APPROVER_SHA256: key.fingerprint },
    durableObjects: { SSH_SESSION: { className: "SshSession", useSQLite: true } },
    async outboundService(req) {
      if (req.url !== "https://approval-peer.invalid/receive" || req.method !== "POST") {
        return new Response(null, { status: 403 });
      }
      const index = commands.indexOf(await req.text());
      received.push(index);
      return index >= 0 && replies[index] ? Response.json(replies[index]) : new Response(null, { status: 422 });
    },
  }, [peer]);
  const { pair, web, serverId, enroll } = await setupPairing(db, request);
  const a = await pair(), b = await pair();
  const call = mcpClient(request, a);
  assert.equal((await enroll(a, wrong.publicKeySpki, {
    ...web, TERNSSH_APPROVER_SHA256: wrong.fingerprint,
  })).status, 403);
  assert.equal((await enroll(a, key.publicKeySpki, { ...web, Authorization: "Bearer " + a.token })).status, 401);
  assert.equal((await enroll(a, key.publicKeySpki)).status, 201);
  assert.equal((await enroll(a, key.publicKeySpki)).status, 409);
  assert.equal((await enroll(b, key.publicKeySpki)).status, 201);
  const enrolled = await (await request(manager + "/state", "GET", web)).json();
  assert.equal(enrolled.tokens.find(x => x.id === a.id).approvalKeyFingerprint, key.fingerprint);


  const ref = { serverId, batchId: randomUUID() };
  const input = { ...ref, commands, timeoutMs: 20_000 };
  const prepared = await call("prepare_command_batch", input);
  const proposal = await call("get_command_batch", ref);
  assert.ok(Boolean(prepared.approvalPayloadBase64));
  assert.ok(prepared.approvalPayloadBase64 === proposal.approvalPayloadBase64);
  assert.ok(proposal.approvalKeyFingerprint === key.fingerprint);
  const bytes = Buffer.from(proposal.approvalPayloadBase64, "base64");
  const envelope = JSON.parse(bytes.toString("utf8"));
  assert.ok(Array.isArray(envelope[12]) && digest(JSON.stringify(envelope[12])) === digest(JSON.stringify(commands)));
  const receipt = { ...ref, digest: proposal.digest };
  const signed = { ...receipt, signature: await key.sign(bytes) };
  await call("approve_command_batch", { ...receipt, approved: true }, -32602);
  await call("approve_command_batch", { ...signed, approved: true }, -32602);
  for (const modified of [[commands[0] + "x", ...commands.slice(1)], [commands[1], commands[0], commands[2]]]) {
    const altered = envelope.slice();
    altered[12] = modified;
    await call("approve_command_batch", { ...receipt, signature: await key.sign(Buffer.from(JSON.stringify(altered))) }, 403);
  }
  await call("approve_command_batch", { ...receipt, signature: await wrong.sign(bytes) }, 403);
  await call("get_command_batch", ref, 404, b);
  const second = await call("prepare_command_batch", input, 200, b);
  assert.notEqual(second.digest, proposal.digest);
  await call("approve_command_batch", { ...signed, digest: second.digest }, 403, b);

  // Seed database time in this isolated fixture. Both the stored challenge and
  // the signature match the past expiry, so expiry is the only rejection reason.
  const old = { serverId, batchId: randomUUID() };
  const expiring = await call("prepare_command_batch", { ...input, ...old });
  const expiredAt = Math.floor(Date.now() / 1000) - 60;
  const cols = "token_id,batch_id,user_id,server_id,server_name,revision,identity_version,timeout_ms,digest,challenge,commands";
  const original = await db.prepare("SELECT " + cols + " FROM mcp_command_batches WHERE token_id=? AND batch_id=?")
    .bind(a.id, old.batchId).first();
  await db.batch([
    db.prepare("DELETE FROM mcp_command_batches WHERE token_id=? AND batch_id=?").bind(a.id, old.batchId),
    db.prepare("INSERT INTO mcp_command_batches(" + cols + ",expires) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(...cols.split(",").map(c => original[c]), expiredAt),
  ]);
  const stale = JSON.parse(Buffer.from(expiring.approvalPayloadBase64, "base64").toString("utf8"));
  stale[15] = expiredAt * 1000;
  await call("approve_command_batch", { ...old, digest: expiring.digest,
    signature: await key.sign(Buffer.from(JSON.stringify(stale))) }, 410);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM mcp_batch_approvals").first("n"), 0);
  assert.equal(received.length, 0);

  const start = await call("approve_command_batch", signed);
  assert.equal(start.batchId, ref.batchId);
  await call("approve_command_batch", signed, 409);
  let batch;
  const deadline = Date.now() + 45_000;
  do {
    batch = await call("get_command_batch_status", receipt);
    if (!batch.running) break;
    await delay(180);
  } while (Date.now() < deadline);
  assert.equal(batch.running, false);
  assert.equal(batch.status, "failed");
  assert.deepEqual(batch.items.map(i => i.status), ["completed", "failed", "skipped"]);
  assert.deepEqual(batch.items.slice(0, 2).map(i => i.exitCode), [0, 37]);
  assert.equal(new Set(batch.items.map(i => i.jobId)).size, 3);
  assert.deepEqual(received, [0, 1]);
  for (const [index, reply] of replies.entries()) {
    const job = { serverId, jobId: batch.items[index].jobId };
    await call("read_job_output", job, 404, b);
    const parts = { stdout: [], stderr: [] };
    let cursor = 0;
    while (true) {
      const page = await call("read_job_output", { ...job, cursor, limit: 3 });
      assert.equal(page.running, false);
      assert.equal(page.outputState, "complete");
      assert.equal(page.exitCode, reply.exitCode);
      for (const frame of page.frames) {
        assert.equal(frame.offset, cursor);
        const part = Buffer.from(frame.base64, "base64");
        parts[frame.stream].push(part);
        cursor += part.length;
      }
      assert.equal(page.nextCursor, cursor);
      if (!page.hasMore) break;
    }
    for (const stream of ["stdout", "stderr"]) assert.equal(digest(Buffer.concat(parts[stream])), digest(reply[stream]));
    const tail = await call("read_job_tail", { ...job, limit: 3 });
    assert.equal(tail.nextCursor, cursor);
    assert.ok(tail.frames.length);
  }
  await call("approve_command_batch", signed, 409);
  assert.deepEqual(received, [0, 1]);
});

test("a deployment without an approver pin denies enrollment and correctly signed legacy receipts", async t => {
  const key = await fixtureKey();
  const { db, request } = await localWorker(t, {
    durableObjects: { SSH_SESSION: { className: "SshSession", useSQLite: true } },
  });
  const { serverId, enroll, pair, web } = await setupPairing(db, request);
  const paired = await pair();
  assert.equal((await enroll(paired, key.publicKeySpki, {
    ...web, TERNSSH_APPROVER_SHA256: key.fingerprint,
  })).status, 403);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM mcp_batch_keys").first("n"), 0);
  const call = mcpClient(request, paired);
  const ref = { serverId, batchId: randomUUID() };
  const p = await call("prepare_command_batch", { ...ref, commands: ["printf 'fixture'"] });
  // Model a key registered before a release lost its pin. Verify a valid
  // signature cannot activate the old pairing even with its record intact.
  await db.prepare("INSERT INTO mcp_batch_keys(token_id,spki,fingerprint) VALUES(?,?,?)")
    .bind(paired.id, key.publicKeySpki, key.fingerprint).run();
  const bytes = Buffer.from(JSON.stringify(["ternssh/batch-approval", 1, "https://ternssh.example", "default", paired.id,
    serverId, p.serverName, p.identityVersion, p.revision, ref.batchId, p.timeoutMs, p.policy, p.commands,
    p.digest, p.challenge, p.expiresAt]));
  const signature = await key.sign(bytes);
  await call("approve_command_batch", { ...ref, digest: p.digest, signature }, 403);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM mcp_batch_approvals").first("n"), 0);
});
