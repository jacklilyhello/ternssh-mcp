import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";
import { localWorker } from "./helpers/local-worker.mjs";
import {
  COMMAND_BATCH_LIMITS as limits, prepareCommandBatch, purgeExpiredCommandBatches, readCommandBatch,
} from "../src/db/mcp-command-batches.ts";
import { issueMcpToken, replaceMcpAuthorization, revokeMcpToken } from "../src/db/mcp-access.ts";
import { OperationError } from "../src/db/mcp-operations.ts";
import { McpBatchExpiry, ensureBatchExpiryAlarm } from "../src/do/mcp-batch-expiry.ts";

async function fixture(t) {
  const { db } = await localWorker(t);
  const userId = "default";
  const serverId = "fixture-server";
  await db.prepare("INSERT INTO credentials(id,user_id,value) VALUES ('fixture-cred',?,'fixture')").bind(userId).run();
  await db.prepare(`INSERT INTO servers(id,user_id,name,host,username,auth_type,credential_ref)
    VALUES (?,?,'Fixture host','test.invalid','fixture','password','fixture-cred')`).bind(serverId, userId).run();
  const identityVersion = await db.prepare("SELECT version FROM mcp_target_identities WHERE server_id=?")
    .bind(serverId).first("version");
  const selection = [{ id: serverId, identityVersion }];
  assert.ok(await replaceMcpAuthorization(db, userId, 0, selection));
  const { id: tokenId } = await issueMcpToken(db, userId);
  const target = { userId, tokenId, serverId, identityVersion, revision: 1 };
  return { db, target, selection };
}

const status = (code) => (error) => error instanceof OperationError && error.status === code;

test("an immutable proposal freezes the authorized host label, scope, policy, timeout and ordered strings", async t => {
  const { db, target, selection } = await fixture(t);
  const batchId = randomUUID();
  const commands = ["  fixture '中文'\t\n", "fixture \"x|y\"\r\n", "fixture 🍊"];
  const input = { batchId, commands, timeoutMs: 7000 };
  const [a, b] = await Promise.all([prepareCommandBatch(db, target, input), prepareCommandBatch(db, target, input)]);
  assert.deepEqual(a, b);
  assert.equal(a.status, "proposed");
  assert.match(a.challenge, /^[0-9a-f]{64}$/);
  assert.deepEqual(a.commands, commands);
  assert.equal(a.serverName, "Fixture host");
  assert.equal(a.identityVersion, target.identityVersion);
  assert.equal(a.revision, target.revision);
  assert.equal(a.policy, "sequential_independent_stop_on_failure_or_unknown");
  const expected = ["ternssh/mcp-command-batch", 1, a.policy, target.userId, target.tokenId, target.serverId,
    target.revision, target.identityVersion, "Fixture host", batchId, 7000, commands];
  assert.equal(a.digest, createHash("sha256").update(JSON.stringify(expected), "utf8").digest("hex"));
  assert.deepEqual(await readCommandBatch(db, target, batchId), a);
  await db.prepare("UPDATE servers SET name='Renamed' WHERE id=?").bind(target.serverId).run();
  assert.deepEqual(await prepareCommandBatch(db, target, input), a);
  await assert.rejects(prepareCommandBatch(db, target, { ...input, timeoutMs: 7001 }), status(409));
  await assert.rejects(prepareCommandBatch(db, target, { ...input, commands: commands.toReversed() }), status(409));
  await assert.rejects(prepareCommandBatch(db, target, { ...input, commands: commands.map(s => s.trim()) }), status(409));
  await assert.rejects(db.prepare("UPDATE mcp_command_batches SET commands='[]' WHERE batch_id=?").bind(batchId).run());

  const other = { ...target, tokenId: (await issueMcpToken(db, target.userId)).id };
  await assert.rejects(readCommandBatch(db, other, batchId), status(404));
  const independent = await prepareCommandBatch(db, other, input);
  assert.notEqual(independent.digest, a.digest);
  assert.notEqual(independent.challenge, a.challenge);
  assert.equal(independent.serverName, "Renamed");
  await assert.rejects(readCommandBatch(db, { ...other, userId: "foreign" }, batchId), status(403));
  assert.ok(await replaceMcpAuthorization(db, target.userId, 1, selection));
  await assert.rejects(readCommandBatch(db, target, batchId), status(403));
  await assert.rejects(readCommandBatch(db, { ...target, revision: 2 }, batchId), status(404));
  await assert.rejects(prepareCommandBatch(db, { ...target, revision: 2 }, input), status(409));
  assert.equal(await db.prepare("SELECT count(commands) AS n FROM mcp_command_batches").first("n"), 0);
  assert.ok(await revokeMcpToken(db, target.userId, target.tokenId));
  assert.equal(await db.prepare("SELECT count(*) AS n FROM mcp_command_batches WHERE token_id=?")
    .bind(target.tokenId).first("n"), 0);
});

test("proposal validation is byte-based and rejects unrepresentable text and oversized JSON before storage", async t => {
  const { db, target } = await fixture(t);
  const batchId = randomUUID();
  for (const [input, code] of [
    [{ commands: [] }, 400], [{ commands: Array(limits.commands + 1).fill("fixture") }, 400],
    [{ commands: ["\u0000"] }, 400], [{ commands: ["\uD800"] }, 400], [{ commands: ["\uDC00"] }, 400],
    [{ commands: [null] }, 400], [{ commands: [" \r\n"] }, 400], [{ batchId: "invalid", commands: ["fixture"] }, 400],
    [{ commands: ["fixture"], timeoutMs: null }, 400], [{ commands: ["fixture"], timeoutMs: 999 }, 400],
    [{ commands: ["🍊".repeat(1024) + "a"] }, 413], [{ commands: Array(3).fill("x".repeat(3000)) }, 413],
    [{ commands: ["synthetic\u001b[31m"] }, 400], [{ commands: ["synthetic\u202e"] }, 400],
    [{ commands: ["x\ry"] }, 400], [{ commands: Array(2).fill('"'.repeat(4000)) }, 413],
  ]) {
    await assert.rejects(prepareCommandBatch(db, target, { batchId, ...input }), status(code));
  }
  assert.equal(await db.prepare("SELECT count(*) AS n FROM mcp_command_batches").first("n"), 0);
  const valid = await prepareCommandBatch(db, target, { batchId, commands: Array(2).fill("🍊".repeat(1024)) });
  assert.equal(valid.commands.length, 2);
  assert.equal(valid.timeoutMs, limits.defaultTimeoutMs);
});

test("expiry, capacity and identity change erase bodies without releasing reserved batch IDs", async t => {
  const { db, target } = await fixture(t);
  const first = { batchId: randomUUID(), commands: ["synthetic"] };
  const live = await prepareCommandBatch(db, target, first);
  // Insert a receipt already past its database deadline without mutating any receipt.
  const expired = randomUUID();
  await db.prepare(`INSERT INTO mcp_command_batches
    SELECT token_id,?,user_id,server_id,server_name,revision,identity_version,timeout_ms,digest,lower(hex(randomblob(32))),commands,unixepoch()-1
    FROM mcp_command_batches WHERE batch_id=?`).bind(expired, first.batchId).run();
  assert.equal(await purgeExpiredCommandBatches(db), 1);
  await assert.rejects(readCommandBatch(db, target, expired), status(410));
  await assert.rejects(prepareCommandBatch(db, target, { batchId: expired, commands: ["different"] }), status(409));
  const inserts = Array.from({ length: limits.activePerToken - 1 }, () => db.prepare(`
    INSERT INTO mcp_command_batches
    SELECT token_id,?,user_id,server_id,server_name,revision,identity_version,timeout_ms,digest,lower(hex(randomblob(32))),commands,expires
    FROM mcp_command_batches WHERE batch_id=?`).bind(randomUUID(), first.batchId));
  await db.batch(inserts);
  await assert.rejects(prepareCommandBatch(db, target, { ...first, batchId: randomUUID() }), status(429));
  assert.deepEqual(await prepareCommandBatch(db, target, first), live);
  await db.prepare("UPDATE servers SET host='changed.invalid' WHERE id=?").bind(target.serverId).run();
  assert.equal(await db.prepare("SELECT count(commands) AS n FROM mcp_command_batches").first("n"), 0);
  await assert.rejects(readCommandBatch(db, target, first.batchId), status(403));
});

test("the idle expiry alarm erases expired proposal and approval bodies while preserving receipts", async t => {
  const { db, target } = await fixture(t);
  const live = await prepareCommandBatch(db, target, { batchId: randomUUID(), commands: ["fixture"] });
  const expired = randomUUID();
  await db.prepare(`INSERT INTO mcp_command_batches
    SELECT token_id,?,user_id,server_id,server_name,revision,identity_version,timeout_ms,digest,lower(hex(randomblob(32))),commands,unixepoch()-1
    FROM mcp_command_batches WHERE batch_id=?`).bind(expired, live.batchId).run();
  const fp = "0".repeat(64);
  // This fixture models an orphaned storage row, without an executable key.
  await db.prepare("INSERT INTO mcp_batch_keys(token_id,spki,fingerprint) VALUES(?,?,?)")
    .bind(target.tokenId, "inert fixture", fp).run();
  await db.prepare(`INSERT INTO mcp_batch_approvals(token_id,batch_id,digest,fingerprint,commands,expires_at)
    SELECT token_id,batch_id,digest,?,commands,unixepoch()*1000-1 FROM mcp_command_batches WHERE batch_id=?`)
    .bind(fp, expired).run();
  let alarmAt = null;
  const ctx = { id: { equals: other => other === "mcp-maintenance:batch-expiry" },
    storage: { getAlarm: async () => alarmAt, setAlarm: async when => { alarmAt = when; } } };
  const env = { DB: db, SSH_SESSION: { idFromName: name => name, get: () => ({
    fetch: (url, init) => cleaner.fetch(new Request(url, init)),
  }) } };
  const cleaner = new McpBatchExpiry(ctx, env);
  await ensureBatchExpiryAlarm(env);
  const firstWake = alarmAt;
  assert.ok(firstWake > Date.now());
  await ensureBatchExpiryAlarm(env);
  assert.equal(alarmAt, firstWake);
  alarmAt = null;
  assert.equal(await cleaner.alarm(), true);
  assert.ok(alarmAt > Date.now());
  assert.equal(await db.prepare("SELECT count(commands) FROM mcp_command_batches").first("count(commands)"), 1);
  assert.equal(await db.prepare("SELECT count(*) FROM mcp_command_batches").first("count(*)"), 2);
  assert.equal(await db.prepare("SELECT count(commands) FROM mcp_batch_approvals").first("count(commands)"), 0);
  assert.equal(await db.prepare("SELECT count(*) FROM mcp_batch_approvals").first("count(*)"), 1);
});
