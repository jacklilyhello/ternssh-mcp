import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { digestToken, issueMcpToken, replaceMcpAuthorization } from "../src/db/mcp-access.ts";
import { reserveDiagnostic, resolveTarget, OperationError } from "../src/db/mcp-operations.ts";
import { checkWorkspaceLease, releaseWorkspaceLease, reserveWorkspaceRequest } from "../src/db/mcp-workspace-leases.ts";
import { localWorker } from "./helpers/local-worker.mjs";

const denied = status => e => e instanceof OperationError && e.status === status;

async function pairedWorkspace(t, count) {
  const { db } = await localWorker(t);
  await db.prepare("INSERT INTO credentials(id,user_id,value) VALUES ('c','default','fixture')").run();
  await db.prepare(`INSERT INTO servers(id,user_id,name,host,username,auth_type,credential_ref)
    VALUES ('s','default','Fixture','s.invalid','fixture','password','c')`).run();
  const identityVersion = await db.prepare("SELECT version FROM mcp_target_identities WHERE server_id='s'").first("version");
  const grant = [{ id: "s", identityVersion, workspaceShell: true }];
  assert.ok(await replaceMcpAuthorization(db, "default", 0, grant));
  const targets = await Promise.all(Array.from({ length: count }, async () => {
    const { token } = await issueMcpToken(db, "default");
    return resolveTarget(db, await digestToken(token), "s");
  }));
  return { db, identityVersion, targets };
}

test("workspace slots bound concurrent pairings and preserve single-use IDs after release", async t => {
  const { db, identityVersion, targets } = await pairedWorkspace(t, 3);
  const ids = targets.map(() => randomUUID());
  const starts = await Promise.allSettled(targets.map((target, i) => reserveWorkspaceRequest(db, target, ids[i], 5000)));
  const active = starts.flatMap((r, i) => r.status === "fulfilled" ? [i] : []);
  const rejected = starts.findIndex(r => r.status === "rejected");
  assert.equal(active.length, 2);
  assert.ok(denied(429)(starts[rejected].reason));
  const i = active[0];
  assert.equal(await reserveWorkspaceRequest(db, targets[i], ids[i], 5000), "workspace-reconcile");
  await checkWorkspaceLease(db, targets[i], ids[i], 5000);
  await releaseWorkspaceLease(db, targets[i], ids[i]);
  await assert.rejects(checkWorkspaceLease(db, targets[i], ids[i], 5000), denied(410));
  assert.equal(await reserveWorkspaceRequest(db, targets[i], ids[i], 5000), "workspace-reconcile");
  assert.equal(await reserveWorkspaceRequest(db, targets[rejected], ids[rejected], 5000), "workspace-start");
  const diagnostic = randomUUID();
  await reserveDiagnostic(db, targets[i], diagnostic);
  await assert.rejects(reserveWorkspaceRequest(db, targets[i], diagnostic, 5000), denied(409));
  await assert.rejects(reserveDiagnostic(db, targets[i], ids[i]), denied(409));
  assert.ok(await replaceMcpAuthorization(db, "default", 1, [{ id: "s", identityVersion }]));
  await assert.rejects(reserveWorkspaceRequest(db, targets[i], ids[i], 5000), denied(403));
});

test("two pairings share 64 starts per host in a rolling hour and retries consume no quota", async t => {
  const { db, targets } = await pairedWorkspace(t, 2);
  const oldest = randomUUID();
  for (let i = 0; i < 64; i++) {
    const target = targets[i % targets.length];
    const id = i === 0 ? oldest : randomUUID();
    assert.equal(await reserveWorkspaceRequest(db, target, id, 5000), "workspace-start");
    await releaseWorkspaceLease(db, target, id);
  }
  const next = randomUUID();
  for (const target of targets) {
    await assert.rejects(reserveWorkspaceRequest(db, target, next, 5000), denied(429));
  }
  assert.equal(await reserveWorkspaceRequest(db, targets[0], oldest, 5000), "workspace-reconcile");

  // Age one released job past the hour without sleeping or relying on the test runner clock.
  await db.prepare("UPDATE mcp_diagnostic_requests SET workspace_started_at=unixepoch()-3601 WHERE token_id=? AND request_id=?")
    .bind(targets[0].tokenId, oldest).run();
  assert.equal(await reserveWorkspaceRequest(db, targets[1], next, 5000), "workspace-start");
  await assert.rejects(reserveWorkspaceRequest(db, targets[0], randomUUID(), 5000), denied(429));
});

test("expired workspace leases free host slots without renewing expired IDs or crossing pairings", async t => {
  const { db, targets: [first, second] } = await pairedWorkspace(t, 2);
  const firstId = randomUUID();
  const secondId = randomUUID();
  const next = randomUUID();
  assert.equal(await reserveWorkspaceRequest(db, first, firstId, 5000), "workspace-start");
  assert.equal(await reserveWorkspaceRequest(db, second, secondId, 5000), "workspace-start");

  await assert.rejects(checkWorkspaceLease(db, second, firstId, 5000), denied(410));
  await releaseWorkspaceLease(db, second, firstId);
  await checkWorkspaceLease(db, first, firstId, 5000);
  await assert.rejects(reserveWorkspaceRequest(db, second, next, 5000), denied(429));

  // A still-occupied slot can have too little time left for safe dispatch.
  await db.prepare("UPDATE mcp_diagnostic_requests SET workspace_lease_until=unixepoch()+60 WHERE token_id=? AND request_id=?")
    .bind(first.tokenId, firstId).run();
  await assert.rejects(checkWorkspaceLease(db, first, firstId, 60_000), denied(410));
  await assert.rejects(reserveWorkspaceRequest(db, second, next, 5000), denied(429));

  await db.prepare("UPDATE mcp_diagnostic_requests SET workspace_lease_until=unixepoch()-1 WHERE token_id=? AND request_id=?")
    .bind(first.tokenId, firstId).run();
  assert.equal(await reserveWorkspaceRequest(db, first, firstId, 5000), "workspace-reconcile");
  await assert.rejects(checkWorkspaceLease(db, first, firstId, 5000), denied(410));
  assert.equal(await reserveWorkspaceRequest(db, second, next, 5000), "workspace-start");
  await checkWorkspaceLease(db, second, secondId, 5000);
  await assert.rejects(reserveWorkspaceRequest(db, first, randomUUID(), 5000), denied(429));
});
