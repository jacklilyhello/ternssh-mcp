import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { localWorker } from "./helpers/local-worker.mjs";

const peer = {
  name: "local-transfer-peer",
  setup(build) {
    build.onResolve({ filter: /^\.\.\/lib\/mcp-(files|ssh)$/ }, args => {
      if (args.importer.endsWith("/routes/mcp-transfers.ts")) {
        return { path: fileURLToPath(new URL("./helpers/transfer-peer.mjs", import.meta.url)) };
      }
    });
  },
};
const digest = data => createHash("sha256").update(data).digest("hex");

test("one-use transfer HTTP route checks bytes, grant, immutable versions and uncertain publication", async t => {
  const { request, raw, db } = await localWorker(t, {}, [peer]);
  const path = "/api/mcp-transfers/";
  const origin = "https://ternssh.example";
  const password = randomUUID();
  const web = { Authorization: "Basic " + Buffer.from("owner:" + password).toString("base64"), Origin: origin, "Content-Type": "application/json" };
  assert.equal((await request("/api/v1/onboarding/setup", "POST", web, { username: "owner", password, confirmPassword: password })).status, 201);
  const manager = "/api/v1/mcp-access";
  const token = (await (await request(manager + "/tokens", "POST", web, {})).json()).token;
  const headers = { Authorization: "Bearer " + token };
  await db.prepare("INSERT INTO credentials(id,user_id,value) VALUES ('c','default','fixture')").run();
  await db.prepare("INSERT INTO servers(id,user_id,name,host,username,auth_type,credential_ref) VALUES ('s','default','Test','test.invalid','test','password','c')").run();
  const { revision, availableServers } = await (await request(manager + "/state", "GET", web)).json();
  await request(manager + "/authorization", "PUT", web, { revision, servers: [{ id: "s", identityVersion: availableServers[0].identityVersion }] });
  await db.batch([
    db.prepare("CREATE TABLE fixture_remote(id TEXT PRIMARY KEY,data BLOB)"),
    db.prepare("CREATE TABLE fixture_mode(mode TEXT)"),
    db.prepare("INSERT INTO fixture_mode VALUES ('normal')"),
    db.prepare("CREATE TABLE fixture_connections(server TEXT)"),
  ]);
  const rpc = async (name, args) => {
    const r = await request("/mcp", "POST", { ...headers, "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: { serverId: "s", ...args } } });
    const result = (await r.json()).result;
    assert.ok(!result.isError);
    return JSON.parse(result.content[0].text);
  };
  const prepare = (body, replaceFileId) => rpc("prepare_upload", { bytes: body.length, sha256: digest(body), replaceFileId });
  const download = fileId => rpc("prepare_download", { fileId });
  const put = (ticket, body, overrides = {}) => raw(path + ticket.operationId, { method: "PUT", body,
    headers: { ...headers, "Content-Type": "application/octet-stream", "X-Content-SHA256": ticket.sha256, ...overrides } });
  const get = ticket => raw(path + ticket.operationId, { headers });
  const count = table => db.prepare("SELECT COUNT(*) AS n FROM " + table).first("n");
  const mode = value => db.prepare("UPDATE fixture_mode SET mode=?").bind(value).run();
  const bytes = Buffer.from([0, 255, 18, 128]);
  const create = await prepare(bytes);
  assert.equal((await raw(path + create.operationId, { method: "HEAD", headers })).status, 405);
  assert.equal((await raw(path + "unknown/extra", { headers })).status, 404);
  assert.equal((await raw(path + create.operationId, { method: "OPTIONS", headers })).status, 405);
  assert.equal((await raw(path + create.operationId, { headers: { ...headers, Origin: "https://elsewhere.invalid" } })).status, 403);
  assert.equal((await get(create)).status, 409);
  assert.equal((await put(create, bytes, { "Content-Type": "text/plain" })).status, 415);
  const [a, b] = await Promise.all([put(create, bytes), put(create, bytes)]);
  const accepted = a.status === 200 ? a : b;
  assert.deepEqual([a.status,b.status].sort(), [200,409]);
  assert.deepEqual(await accepted.json(), { status: "uploaded", fileId: create.fileId, bytes: bytes.length, sha256: digest(bytes) });
  assert.equal(await count("fixture_connections"), 1);
  const read = await download(create.fileId);
  const response = await get(read);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("X-Content-SHA256"), digest(bytes));
  assert.equal(response.headers.get("Content-Length"), String(bytes.length));
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
  assert.equal((await get(read)).status, 409);
  const audited = () => db.prepare("SELECT COUNT(*) AS n FROM mcp_recent_calls WHERE result='downloaded'").first("n");
  assert.equal(await audited(), 1);

  const oldReader = await download(create.fileId);
  const replacement = Buffer.from("new");
  const update = await prepare(replacement, create.fileId);
  const updated = await put(update, replacement);
  assert.equal(updated.status, 200);
  assert.equal((await updated.json()).fileId, create.fileId);
  assert.equal(await count("fixture_remote"), 1);
  assert.equal((await get(oldReader)).status, 409);
  assert.equal(await audited(), 1);

  const connections = await count("fixture_connections");
  const badDigest = await prepare(bytes);
  assert.equal((await put(badDigest, Buffer.from([1, 1, 1, 1]))).status, 400);
  assert.equal((await put(badDigest, bytes)).status, 409);
  const tooLong = await prepare(bytes);
  // No declared length; the handler must still cap the actual stream before opening SSH.
  const chunks = new ReadableStream({ start(c) { c.enqueue(bytes); c.enqueue(bytes); c.close(); } });
  const over = await raw(path + tooLong.operationId, { method: "PUT", body: chunks, duplex: "half",
    headers: { ...headers, "Content-Type": "application/octet-stream", "X-Content-SHA256": tooLong.sha256 } });
  assert.equal(over.status, 413);
  assert.equal(await count("fixture_connections"), connections);

  await mode("hold-channel");
  const slow = await prepare(bytes);
  await db.prepare("UPDATE mcp_transfers SET expires=unixepoch()+2 WHERE id=?").bind(slow.operationId).run();
  const timeout = await put(slow, bytes);
  assert.equal(timeout.status, 504);
  assert.equal((await timeout.json()).status, "timeout");
  assert.equal((await put(slow, bytes)).status, 409);

  await mode("replace");
  const loser = await prepare(bytes, create.fileId);
  assert.equal((await put(loser, bytes)).status, 409);
  assert.equal(await count("fixture_remote"), 1, "known CAS loser cleans only its new object");
  await mode("lost-rename");
  const unknown = await prepare(bytes);
  const uncertain = await put(unknown, bytes);
  assert.equal(uncertain.status, 502);
  assert.equal((await uncertain.json()).status, "unknown");
  assert.equal((await put(unknown, bytes)).status, 409);
  assert.equal(await count("fixture_remote"), 2, "no destructive cleanup after a lost acknowledgement");
  await mode("normal");
  await db.prepare("CREATE TRIGGER fail_publish BEFORE INSERT ON mcp_files BEGIN SELECT RAISE(ABORT,'fixture publication fault'); END").run();
  const dbUnknown = await prepare(bytes);
  assert.equal((await (await put(dbUnknown, bytes)).json()).status, "unknown");
  assert.equal(await count("fixture_remote"), 3, "publication transport error preserves the possible live object");
  await db.prepare("DROP TRIGGER fail_publish").run();

  await db.prepare("CREATE TRIGGER fail_audit BEFORE INSERT ON mcp_recent_calls WHEN NEW.result='uploaded' BEGIN SELECT RAISE(ABORT,'fixture audit fault'); END").run();
  const afterCommit = await prepare(bytes);
  assert.equal((await put(afterCommit, bytes)).status, 200);
  assert.equal((await put(afterCommit, bytes)).status, 409);
  const failedRead = await download(afterCommit.fileId);
  await db.prepare("DELETE FROM fixture_remote").run();
  const failure = await get(failedRead);
  assert.equal(failure.status, 502);
  assert.ok(!(await failure.text()).includes("private fixture"));
  assert.equal(await audited(), 1);
  const revoked = await prepare(bytes);
  assert.equal((await request(manager + "/authorization", "DELETE", web)).status, 200);
  assert.equal((await put(revoked, bytes)).status, 409);
});
