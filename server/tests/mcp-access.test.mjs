import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { Hono } from "hono";
import { authenticateMcpToken, checkWorkspaceGrant, digestToken, listMcpAuthorizedServers } from "../src/db/mcp-access.ts";
import {
  checkTarget, checkTransfer, claimTransfer, OperationError, prepareTransfer,
  publishUpload, recordResult, reserveDiagnostic, resolveTarget,
} from "../src/db/mcp-operations.ts";
import { resetUserData } from "../src/db/reset-user-data.ts";
import { getPinnedMcpConfig, recordWebHostKey, webTargetVersion } from "../src/db/mcp-host-keys.ts";
import { runMcpDiagnostic } from "../src/lib/mcp-ssh.ts";
import { mcpAccessRoutes } from "../src/routes/mcp-access.ts";

const origin = "https://test.example";
const migrations = new URL("../migrations/", import.meta.url);

function fixture(t) {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  sqlite.exec("PRAGMA foreign_keys = ON");
  const scripts = readdirSync(migrations).filter((name) => name.endsWith(".sql")).sort();
  for (const name of scripts.filter((name) => name < "0010")) {
    sqlite.exec(readFileSync(new URL(name, migrations), "utf8"));
  }
  sqlite.exec("INSERT INTO users (id) VALUES ('other')");
  function insertServer(id, owner = "default") {
    sqlite.prepare(`INSERT OR IGNORE INTO credentials (id,user_id,value) VALUES (?,?,?)`)
      .run(id, owner, "test-fixture-credential");
    sqlite.prepare(`INSERT INTO servers (id,user_id,name,host,username,auth_type,credential_ref)
      VALUES (?,?,?,'server.example','tester','password',?)`).run(id, owner, id, id);
  }
  insertServer("A");
  for (const name of scripts.filter((name) => name >= "0010")) {
    sqlite.exec(readFileSync(new URL(name, migrations), "utf8"));
  }
  insertServer("B");
  insertServer("C", "other");

  // Run the production queries and migrations against SQLite, with D1 batch transaction semantics.
  const db = {
    withSession(constraint) {
      assert.equal(constraint, "first-primary");
      return this;
    },
    prepare(sql) {
      const statement = sqlite.prepare(sql);
      const bound = (args) => ({
        bind: (...values) => bound(values),
        first: (column) => {
          const row = statement.get(...args);
          return column ? row?.[column] ?? null : row ?? null;
        },
        run: () => ({ meta: { changes: statement.run(...args).changes } }),
        all: () => {
          const results = statement.all(...args);
          const { changes } = sqlite.prepare("SELECT changes() AS changes").get();
          return { results, meta: { changes } };
        },
      });
      return bound([]);
    },
    batch(statements) {
      sqlite.exec("BEGIN");
      try {
        const result = statements.map((statement) => statement.all());
        sqlite.exec("COMMIT");
        return result;
      } catch (error) {
        sqlite.exec("ROLLBACK");
        throw error;
      }
    },
  };
  const app = new Hono();
  app.use("*", async (c, next) => {
    c.set("user", { id: "default" });
    await next();
  });
  app.route("/api/v1/mcp-access", mcpAccessRoutes);
  function request(path, method = "GET", data, headers = {}) {
    return app.request(origin + "/api/v1/mcp-access" + path, {
      method,
      headers: { Origin: origin, "Content-Type": "application/json", ...headers },
      body: data === undefined ? undefined : JSON.stringify(data),
    }, { DB: db });
  }
  const state = async () => (await request("/state")).json();
  const confirm = (revision, servers) => request("/authorization", "PUT", { revision, servers });
  const pair = async () => {
    const response = await request("/tokens", "POST", {});
    assert.equal(response.status, 201);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    return response.json();
  };
  return { sqlite, db, insertServer, request, state, confirm, pair };
}

test("host pins belong to one authenticated target incarnation, including late observations and address changes", async (t) => {
  const { db, sqlite } = fixture(t);
  const record = sqlite.prepare("SELECT * FROM servers WHERE id = 'A'").get();
  const target = { serverId: "A", userId: "default", identityVersion: await webTargetVersion(db, record) };
  const first = "SHA256:" + "a".repeat(43);
  const other = "SHA256:" + "b".repeat(43);
  assert.equal(await getPinnedMcpConfig(db, target), null);
  const unpinned = await runMcpDiagnostic(db, target, "utc", async () => {});
  assert.equal(unpinned.status, "failed");
  assert.equal(unpinned.exitCode, null);
  assert.match(unpinned.error, /verified host key is required/);
  const revoked = new Error("scope revoked");
  await assert.rejects(runMcpDiagnostic(db, target, "utc", async () => { throw revoked; }), (error) => error === revoked);
  await recordWebHostKey(db, target, first);
  await recordWebHostKey(db, target, other);
  assert.equal((await getPinnedMcpConfig(db, target)).expectedFingerprint, first);
  assert.equal(await getPinnedMcpConfig(db, { ...target, userId: "other" }), null);
  sqlite.exec("UPDATE servers SET host = 'replacement.invalid' WHERE id = 'A'");
  assert.equal(await webTargetVersion(db, record), null);
  assert.equal(await getPinnedMcpConfig(db, target), null);
  const fresh = { ...target, identityVersion: await webTargetVersion(db, { ...record, host: "replacement.invalid" }) };
  await recordWebHostKey(db, target, other);
  assert.equal(await getPinnedMcpConfig(db, fresh), null);
  await recordWebHostKey(db, fresh, other);
  assert.equal((await getPinnedMcpConfig(db, fresh)).expectedFingerprint, other);
  await recordWebHostKey(db, target, first);
  assert.equal((await getPinnedMcpConfig(db, fresh)).expectedFingerprint, other);
});

test("confirm replaces the complete valid selection, rejects stale or foreign records, and preserves pairings on end", async (t) => {
  const { db, sqlite, state, confirm, pair, request } = fixture(t);
  const first = await state();
  const [a, b] = first.availableServers;
  assert.deepEqual(first.authorizedServerIds, []);
  assert.deepEqual(first.tokens, []);
  assert.deepEqual(first.availableServers.map(({ id }) => id), ["A", "B"]);
  const { token } = await pair();
  assert.deepEqual(await listMcpAuthorizedServers(db, token), []);
  assert.equal((await confirm(0, [a, b])).status, 200);
  assert.equal((await confirm(0, [a])).status, 409);
  const foreign = sqlite.prepare("SELECT server_id AS id, version AS identityVersion FROM mcp_target_identities WHERE server_id='C'").get();
  assert.equal((await confirm(1, [b, foreign])).status, 409);
  assert.deepEqual((await state()).authorizedServerIds, ["A", "B"]);
  assert.equal((await confirm(1, [b])).status, 200);
  assert.deepEqual(await listMcpAuthorizedServers(db, token), [{ id: "B", name: "B" }]);
  assert.equal((await request("/authorization", "DELETE")).status, 200);
  assert.deepEqual(await listMcpAuthorizedServers(db, token), []);
  assert.equal((await confirm(2, [a])).status, 409);
  assert.equal(await authenticateMcpToken(db, token), true);
});

test("workspace commands require per-host opt-in on the current owner, pairing, identity and revision", async t => {
  const { sqlite, db, state, confirm, request, pair } = fixture(t);
  const [a, b] = (await state()).availableServers;
  const first = await pair();
  const second = await pair();
  const digest = await digestToken(first.token);
  const currentTarget = host => resolveTarget(db, digest, host.id);
  const denied = target => assert.rejects(checkWorkspaceGrant(db, target), hasStatus(403));

  assert.equal((await confirm(0, [a, b])).status, 200);
  const legacy = await currentTarget(a);
  await denied(legacy);
  for (const invalid of [1, "true", null]) {
    assert.equal((await confirm(1, [{ ...a, workspaceShell: invalid }])).status, 400);
  }
  assert.equal((await confirm(1, [{ ...a, workspaceShell: true }, b])).status, 200);
  const target = await currentTarget(a);
  await checkWorkspaceGrant(db, target);
  await denied(legacy);
  await denied(await currentTarget(b));
  await denied({ ...target, userId: "other" });
  await denied({ ...target, identityVersion: "stale" });
  await denied({ ...target, tokenId: "unknown" });
  assert.deepEqual((await state()).availableServers, [{ ...a, workspaceShell: true }, b]);
  assert.deepEqual(await listMcpAuthorizedServers(db, first.token), [
    { id: a.id, name: a.name, workspaceShell: true }, { id: b.id, name: b.name },
  ]);

  assert.equal((await confirm(2, [{ ...a, workspaceShell: false }, b])).status, 200);
  await denied(target);
  await denied(await currentTarget(a));
  assert.equal((await confirm(3, [{ ...a, workspaceShell: true }])).status, 200);
  const renewed = await currentTarget(a);
  assert.equal((await request("/tokens/" + first.id, "DELETE")).status, 200);
  await denied(renewed);
  const survivor = await resolveTarget(db, await digestToken(second.token), a.id);
  await checkWorkspaceGrant(db, survivor);
  sqlite.exec("UPDATE servers SET username='changed' WHERE id='A'");
  await denied(survivor);
  assert.deepEqual(await listMcpAuthorizedServers(db, second.token), []);
});

test("rename preserves access, endpoint changes and deletion invalidate even old or restored identifiers", async (t) => {
  const { db, sqlite, state, confirm, pair, insertServer } = fixture(t);
  const { token } = await pair();
  let revision = 0;
  const selectA = async () => {
    const [a] = (await state()).availableServers;
    assert.equal((await confirm(revision++, [a])).status, 200);
    return a;
  };
  let old = await selectA();
  sqlite.exec("UPDATE servers SET name = 'A renamed', host=host WHERE id='A'");
  assert.deepEqual(await listMcpAuthorizedServers(db, token), [{ id: "A", name: "A renamed" }]);
  for (const edit of [
    "UPDATE servers SET host='changed.example' WHERE id='A'; UPDATE servers SET host='server.example' WHERE id='A'",
    "UPDATE servers SET port=2200 WHERE id='A'",
    "UPDATE servers SET username='another-user' WHERE id='A'",
  ]) {
    sqlite.exec(edit);
    assert.deepEqual(await listMcpAuthorizedServers(db, token), []);
    assert.equal((await confirm(revision, [old])).status, 409);
    old = await selectA();
  }
  sqlite.exec("DELETE FROM servers WHERE id='A'");
  insertServer("A");
  assert.deepEqual(await listMcpAuthorizedServers(db, token), []);
  assert.equal((await confirm(revision, [old])).status, 409);
});

test("dedicated tokens are stored as digests, independently revocable, and audits are bounded metadata", async (t) => {
  const { db, sqlite, state, pair, request } = fixture(t);
  const first = await pair();
  const second = await pair();
  const stored = sqlite.prepare("SELECT id, digest FROM mcp_tokens WHERE id=?").get(first.id);
  assert.match(stored.digest, /^[a-f\d]{64}$/);
  assert.notEqual(stored.digest, first.token);
  assert.notEqual(first.token, second.token);
  assert.equal(await authenticateMcpToken(db, first.id), false);
  assert.equal(await authenticateMcpToken(db, stored.digest), false);
  assert.equal(await listMcpAuthorizedServers(db, ""), null);
  assert.equal((await request("/tokens/" + first.id, "DELETE")).status, 200);
  assert.equal(await authenticateMcpToken(db, first.token), false);
  assert.equal(await listMcpAuthorizedServers(db, first.token), null);
  for (let i = 0; i < 23; i++) assert.deepEqual(await listMcpAuthorizedServers(db, second.token), []);
  const current = await state();
  assert.equal(current.recentCalls.length, 20);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM mcp_recent_calls").get().n, 20);
  assert.deepEqual(current.tokens, [{ id: second.id, createdAt: second.createdAt }]);
  assert.deepEqual(Object.keys(current.recentCalls[0]).sort(), ["at", "result", "target"]);
  for (const secret of [first.token, second.token, stored.digest, "test-fixture-credential", "server.example"]) {
    assert.ok(!JSON.stringify(current).includes(secret));
  }
});

test("management rejects cross-origin requests, forged selections, and non-JSON changes", async (t) => {
  const { request, confirm, state } = fixture(t);
  const [a] = (await state()).availableServers;
  assert.equal((await request("/tokens", "POST", {}, { Origin: "https://foreign.example" })).status, 403);
  assert.equal((await request("/authorization", "DELETE", undefined, { Origin: "" })).status, 403);
  assert.equal((await request("/state", "GET", undefined, { Origin: "https://foreign.example" })).status, 403);
  assert.equal((await request("/tokens", "POST", {}, { "Content-Type": "text/plain" })).status, 415);
  assert.equal((await confirm(0, [a, a])).status, 400);
  assert.equal((await confirm(0, [{ id: a.id, identityVersion: "0".repeat(32) }])).status, 409);
  assert.equal((await confirm(-1, [a])).status, 400);
  assert.deepEqual((await state()).tokens, []);
  assert.equal((await state()).revision, 0);
});

test("concurrent confirmations have one winner; an ended or reset workspace cannot reuse a stale choice", async (t) => {
  const { db, request, state, confirm, pair } = fixture(t);
  const { token } = await pair();
  const { availableServers: [a, b] } = await state();
  const confirmations = await Promise.all([confirm(0, [a]), confirm(0, [b])]);
  assert.deepEqual(confirmations.map((response) => response.status).sort(), [200, 409]);
  assert.equal((await state()).authorizedServerIds.length, 1);
  await request("/authorization", "DELETE");
  assert.equal((await confirm(1, [a])).status, 409);
  assert.deepEqual(await listMcpAuthorizedServers(db, token), []);
  await resetUserData(db, "default");
  assert.equal(await authenticateMcpToken(db, token), false);
  assert.equal(await listMcpAuthorizedServers(db, token), null);
  assert.deepEqual(await state(), {
    revision: 0, availableServers: [], authorizedServerIds: [], tokens: [], recentCalls: [],
  });
  assert.equal((await confirm(0, [a])).status, 409);
});

const uploadSpec = { direction: "upload", bytes: 12, sha256: "a".repeat(64) };

async function pairedTarget(t, ids = ["A"]) {
  const ctx = fixture(t);
  const { availableServers } = await ctx.state();
  assert.equal((await ctx.confirm(0, availableServers.filter((s) => ids.includes(s.id)))).status, 200);
  const pairing = await ctx.pair();
  const digest = await digestToken(pairing.token);
  return { ...ctx, pairing, digest, target: await resolveTarget(ctx.db, digest, "A") };
}

function hasStatus(status) {
  return (error) => error instanceof OperationError && error.status === status;
}

function oneWinner(outcomes, status = 409) {
  const accepted = outcomes.filter((result) => result.status === "fulfilled");
  const denied = outcomes.filter((result) => result.status === "rejected");
  assert.equal(accepted.length, 1);
  assert.equal(denied.length, outcomes.length - 1);
  for (const entry of denied) assert.ok(hasStatus(status)(entry.reason));
  return accepted[0].value;
}

test("transfer and diagnostic requests require a currently authorized direct target and the issuing pairing", async (t) => {
  const { db, target, digest, pair, pairing, request } = await pairedTarget(t);
  for (const forbidden of ["B", "C", "missing"]) {
    await assert.rejects(resolveTarget(db, digest, forbidden), hasStatus(403));
  }
  const ticket = await prepareTransfer(db, target, uploadSpec);
  const second = await digestToken((await pair()).token);
  await assert.rejects(claimTransfer(db, second, ticket.operationId, "upload"), hasStatus(409));
  await assert.rejects(claimTransfer(db, digest, ticket.operationId, "download"), hasStatus(409));
  const claimed = oneWinner(await Promise.allSettled([
    claimTransfer(db, digest, ticket.operationId, "upload"),
    claimTransfer(db, digest, ticket.operationId, "upload"),
  ]));
  assert.equal(claimed.fileId, ticket.fileId);
  assert.equal(claimed.tokenId, pairing.id);
  assert.equal(claimed.serverId, "A");
  await checkTransfer(db, claimed);
  await request("/tokens/" + pairing.id, "DELETE");
  await assert.rejects(checkTransfer(db, claimed), hasStatus(409));
  await assert.rejects(publishUpload(db, claimed), hasStatus(409));
  await assert.rejects(resolveTarget(db, digest, "A"), hasStatus(403));
  await checkTarget(db, await resolveTarget(db, second, "A"));
});

test("ending and re-confirming the same server cannot revive old tickets or replay a diagnostic", async (t) => {
  const { db, target, digest, request, state, confirm } = await pairedTarget(t);
  const id = crypto.randomUUID();
  oneWinner(await Promise.allSettled([reserveDiagnostic(db, target, id), reserveDiagnostic(db, target, id)]));
  const pending = await prepareTransfer(db, target, uploadSpec);
  const inProgress = await prepareTransfer(db, target, uploadSpec);
  const item = await claimTransfer(db, digest, inProgress.operationId, "upload");
  await request("/authorization", "DELETE");
  const snapshot = await state();
  const [a] = snapshot.availableServers;
  assert.equal((await confirm(snapshot.revision, [a])).status, 200);
  const fresh = await resolveTarget(db, digest, "A");
  assert.ok(fresh.revision > target.revision);
  await assert.rejects(claimTransfer(db, digest, pending.operationId, "upload"), hasStatus(409));
  await assert.rejects(checkTransfer(db, item), hasStatus(409));
  await assert.rejects(publishUpload(db, item), hasStatus(409));
  await assert.rejects(prepareTransfer(db, target, uploadSpec), hasStatus(409));
  await assert.rejects(reserveDiagnostic(db, fresh, id), hasStatus(409));
  await reserveDiagnostic(db, fresh, crypto.randomUUID());
});

test("file handles are scoped to the record and host identity, including address changes back to the original", async (t) => {
  const { db, sqlite, digest, target, confirm, state } = await pairedTarget(t, ["A", "B"]);
  const first = await prepareTransfer(db, target, uploadSpec);
  const item = await claimTransfer(db, digest, first.operationId, "upload");
  await publishUpload(db, item);
  const get = { direction: "download", fileId: first.fileId };
  const replace = { ...uploadSpec, replaceFileId: first.fileId };
  const b = await resolveTarget(db, digest, "B");
  for (const spec of [get, replace]) await assert.rejects(prepareTransfer(db, b, spec), hasStatus(404));
  const ticket = await prepareTransfer(db, target, get);
  sqlite.exec("UPDATE servers SET name='Display rename' WHERE id='A'");
  await checkTransfer(db, await claimTransfer(db, digest, ticket.operationId, "download"));
  const pending = await prepareTransfer(db, target, get);
  sqlite.exec("UPDATE servers SET host='other.invalid' WHERE id='A'; UPDATE servers SET host='server.example' WHERE id='A'");
  await assert.rejects(resolveTarget(db, digest, "A"), hasStatus(403));
  const current = await state();
  assert.equal((await confirm(current.revision, current.availableServers)).status, 200);
  const changed = await resolveTarget(db, digest, "A");
  assert.notEqual(changed.identityVersion, target.identityVersion);
  for (const spec of [get, replace]) await assert.rejects(prepareTransfer(db, changed, spec), hasStatus(404));
  await assert.rejects(claimTransfer(db, digest, pending.operationId, "download"), hasStatus(409));
});

test("concurrent replacements publish only one complete version and invalidate earlier download tickets", async (t) => {
  const { db, target, digest } = await pairedTarget(t);
  const initial = await prepareTransfer(db, target, uploadSpec);
  const claim = (receipt, direction) => claimTransfer(db, digest, receipt.operationId, direction);
  await publishUpload(db, await claim(initial, "upload"));
  const get = { direction: "download", fileId: initial.fileId };
  const oldDownload = await prepareTransfer(db, target, get);
  const oldClaimed = await claim(await prepareTransfer(db, target, get), "download");
  const put = async (sha256) => claim(await prepareTransfer(db, target, {
    ...uploadSpec, sha256, replaceFileId: initial.fileId,
  }), "upload");
  const [x, y] = await Promise.all([put("b".repeat(64)), put("c".repeat(64))]);
  const outcomes = await Promise.allSettled([publishUpload(db, x), publishUpload(db, y)]);
  oneWinner(outcomes);
  const winner = outcomes[0].status === "fulfilled" ? x : y;
  const current = await prepareTransfer(db, target, get);
  assert.equal(current.fileId, initial.fileId);
  assert.equal(current.sha256, winner.sha256);
  assert.equal((await claim(current, "download")).storageId, winner.storageId);
  await assert.rejects(claim(oldDownload, "download"), hasStatus(409));
  await assert.rejects(checkTransfer(db, oldClaimed), hasStatus(409));
});

test("expired operations cannot start or continue, and diagnostic audit entries contain only metadata", async (t) => {
  const { db, sqlite, target, digest, state } = await pairedTarget(t);
  const expired = await prepareTransfer(db, target, uploadSpec);
  sqlite.prepare("UPDATE mcp_transfers SET expires=unixepoch()-1 WHERE id=?").run(expired.operationId);
  await assert.rejects(claimTransfer(db, digest, expired.operationId, "upload"), hasStatus(409));
  const live = await prepareTransfer(db, target, uploadSpec);
  const claimed = await claimTransfer(db, digest, live.operationId, "upload");
  for (const result of ["completed", "failed", "unknown", "timeout", "uploaded", "downloaded"]) {
    await recordResult(db, target, result);
  }
  const { recentCalls } = await state();
  assert.deepEqual(recentCalls.map((c) => c.result), ["downloaded", "uploaded", "timeout", "unknown", "failed", "completed"]);
  for (const entry of recentCalls) {
    assert.equal(entry.target, "A");
    assert.deepEqual(Object.keys(entry).sort(), ["at", "result", "target"]);
  }
  t.mock.timers.enable({ apis: ["Date"], now: claimed.expires * 1000 });
  await assert.rejects(checkTransfer(db, claimed), hasStatus(410));
});
