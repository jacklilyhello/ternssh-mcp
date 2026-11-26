import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { test } from "node:test";
import { localWorker } from "./helpers/local-worker.mjs";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const origin = "https://ternssh.example";
const manager = "/api/v1/mcp-access";

async function seedServers(db) {
  await db.prepare("INSERT INTO credentials (id, user_id, value) VALUES ('test-cred','default','fixture')").run();
  await db.prepare(`INSERT INTO servers (id, user_id, name, host, username, auth_type, credential_ref)
    VALUES ('a','default','A','a.invalid','test','password','test-cred'),
           ('b','default','B','b.invalid','test','password','test-cred')`).run();
}

test("MCP transport, web authentication and scope replacement through the Worker", async (t) => {
  let connectionAttempts = 0;
  const socketSpy = {
    name: "count-mcp-connections",
    setup(builder) {
      builder.onResolve({ filter: /^\.\/resolve-host$/ }, ({ importer }) =>
        importer.endsWith("/lib/mcp-ssh.ts") ? { path: "ssh", namespace: "mcp-spy" } : undefined);
      builder.onLoad({ filter: /^ssh$/, namespace: "mcp-spy" }, () => ({
        contents: `export async function connectToHost() {
          await fetch("https://socket-spy.invalid/attempt");
          throw new Error("SSH unavailable in this fixture");
        }`,
      }));
    },
  };
  const { request, raw, db } = await localWorker(t, {
    durableObjects: { SSH_SESSION: { className: "SshSession", useSQLite: true } },
    outboundService() {
      connectionAttempts++;
      return new Response(null, { status: 403 });
    },
  }, [socketSpy]);
  const password = randomUUID();
  const webHeaders = {
    Authorization: "Basic " + Buffer.from("owner:" + password).toString("base64"),
    Origin: origin, "Content-Type": "application/json",
  };
  assert.deepEqual(await (await request("/api/health")).json(), { ok: true });
  for (const path of ["/api/v1/me/reset", "/api/v1/dashboards/reset"]) {
    assert.equal((await request(path, "POST", { ...webHeaders, Origin: "https://foreign.example" })).status, 403);
  }
  const tokenLike = "tmcp_" + "x".repeat(43);
  assert.equal((await request("/mcp", "POST", { Authorization: "Bearer " + tokenLike })).status, 403);
  assert.equal((await request(manager + "/state")).status, 403);
  assert.equal((await request("/api/v1/onboarding/setup", "POST", webHeaders,
    { username: "owner", password, confirmPassword: password })).status, 201);

  assert.equal((await request(manager + "/tokens", "POST", { ...webHeaders, Origin: "https://cross-site.example" }, {})).status, 403);
  const created = await request(manager + "/tokens", "POST", webHeaders, {});
  assert.equal(created.status, 201);
  assert.equal(created.headers.get("cache-control"), "no-store");
  const pairing = await created.json();
  const rpcHeaders = {
    Authorization: "Bearer " + pairing.token,
    "Content-Type": "application/json", Accept: "application/json, text/event-stream",
  };
  const rpc = (method, params, overrides = {}) => request("/mcp", "POST", { ...rpcHeaders, ...overrides },
    { jsonrpc: "2.0", id: 1, method, params });
  const list = async () => {
    const response = await rpc("tools/call", { name: "list_authorized_servers", arguments: {} });
    assert.equal(response.status, 200);
    const data = await response.json();
    return JSON.parse(data.result.content[0].text).servers;
  };
  assert.equal((await rpc("ping", {}, { Authorization: "" })).status, 401);
  assert.equal((await rpc("ping", {}, { Authorization: webHeaders.Authorization })).status, 401);
  assert.equal((await rpc("ping", {}, { Authorization: "Bearer " + tokenLike })).status, 401);
  assert.equal((await request(manager + "/state", "GET", rpcHeaders)).status, 401);
  assert.equal((await request("/api/v1/servers/missing/credential", "GET", rpcHeaders)).status, 401);
  assert.equal((await rpc("ping", {}, { Origin: "https://cross-site.example" })).status, 403);
  assert.equal((await rpc("ping", {}, { Accept: "text/html" })).status, 406);
  assert.equal((await rpc("ping", {}, { "Content-Type": "text/plain" })).status, 415);
  assert.equal((await rpc("ping", {}, { "MCP-Protocol-Version": "unknown" })).status, 400);
  assert.equal((await rpc("ping", { large: "x".repeat(17000) })).status, 413);
  assert.equal((await request("/mcp", "GET", rpcHeaders)).status, 405);

  const init = await rpc("initialize", {
    protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "test", version: "1" },
  });
  assert.equal((await init.json()).result.protocolVersion, "2025-11-25");
  const notification = await request("/mcp", "POST", rpcHeaders,
    { jsonrpc: "2.0", method: "notifications/initialized" });
  assert.equal(notification.status, 202);
  assert.equal(await notification.text(), "");
  const catalog = await (await rpc("tools/list", {})).json();
  assert.deepEqual(catalog.result.tools.map(({ name }) => name).sort(),
    ["approve_command_batch", "cancel_command_batch", "cancel_job", "get_command_batch", "get_command_batch_status", "get_job_status", "list_authorized_servers", "prepare_command_batch", "prepare_download", "prepare_upload",
      "read_job_output", "read_job_tail", "run_diagnostic", "run_workspace_command"]);
  for (const tool of catalog.result.tools) assert.equal(tool.inputSchema.additionalProperties, false);
  const tailSchema = catalog.result.tools.find(({ name }) => name === "read_job_tail").inputSchema;
  assert.deepEqual(tailSchema.properties.stream, { type: "string", enum: ["stdout", "stderr"] });
  assert.ok(!tailSchema.required.includes("stream"));
  const invalid = await (await rpc("tools/call", { name: "grant_server" })).json();
  assert.equal(invalid.error.code, -32602);
  assert.deepEqual(await list(), []);

  await seedServers(db);
  const state = async () => (await request(manager + "/state", "GET", webHeaders)).json();
  const select = async (id) => {
    const { revision, availableServers } = await state();
    const { identityVersion } = availableServers.find((server) => server.id === id);
    return request(manager + "/authorization", "PUT", webHeaders, { revision, servers: [{ id, identityVersion }] });
  };
  assert.equal((await select("a")).status, 200);
  assert.deepEqual(await list(), [{ id: "a", name: "A" }]);
  await t.test("tool arguments, direct target checks, unpinned SSH and file transfer routes", async () => {
    async function call(name, args) {
      const response = await rpc("tools/call", { name, arguments: args });
      assert.equal(response.status, 200);
      return response.json();
    }
    function content(response, failed = false) {
      assert.equal(response.result.isError ?? false, failed);
      return JSON.parse(response.result.content[0].text);
    }

    const serverId = "a";
    const diag = { serverId, diagnostic: "utc", requestId: randomUUID() };
    const bytes = Uint8Array.from([0, 1, 254, 255]);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const put = { serverId, bytes: bytes.length, sha256 };
    const get = { serverId, fileId: randomUUID() };
    for (const [tool, args] of [
      ["run_diagnostic", { ...diag, command: "unexpected" }],
      ["run_diagnostic", { ...diag, asJob: true, command: "unexpected" }],
      ["run_diagnostic", { ...diag, timeoutMs: 30000 }],
      ["run_diagnostic", { ...diag, asJob: true, timeoutMs: 0 }],
      ["read_job_output", { serverId, jobId: diag.requestId, cursor: -1 }],
      ["read_job_tail", { serverId, jobId: diag.requestId, limit: 32769 }],
      ["read_job_tail", { serverId, jobId: diag.requestId, stream: "both" }],
      ["read_job_tail", { serverId, jobId: diag.requestId, stream: null }],
      ["read_job_tail", { serverId, jobId: diag.requestId, stream: {} }],
      ["read_job_tail", { serverId, jobId: diag.requestId, stream: "stdout", cursor: 0 }],
      ["read_job_output", { serverId, jobId: diag.requestId, stream: "stderr" }],
      ["get_job_status", { serverId, jobId: diag.requestId, stream: "stdout" }],
      ["cancel_job", { serverId, jobId: diag.requestId, stream: "stderr" }],
      ["run_diagnostic", { ...diag, diagnostic: "unknown-diagnostic" }],
      ["run_diagnostic", { ...diag, requestId: "invalid" }],
      ["run_workspace_command", { serverId, requestId: diag.requestId, command: "spec", hostDirectory: "/" }],
      ["run_workspace_command", { serverId, requestId: diag.requestId, command: "spec", timeoutMs: 0 }],
      ["prepare_upload", { ...put, path: "unmanaged" }],
      ["prepare_upload", { ...put, bytes: 1048577 }],
      ["prepare_upload", { ...put, bytes: 1.25 }],
      ["prepare_upload", { ...put, sha256: "invalid" }],
      ["prepare_upload", { ...put, replaceFileId: "invalid" }],
      ["prepare_download", { ...get, path: "unmanaged" }],
    ]) {
      const response = await call(tool, args);
      assert.equal(response.error.code, -32602);
    }
    for (const [tool, args] of [["run_diagnostic", diag], ["prepare_upload", put], ["prepare_download", get]]) {
      const denial = content(await call(tool, { ...args, serverId: "b" }), true);
      assert.equal(denial.code, 403);
    }
    // The invalid calls never reserve a request or transfer ahead of a connection.
    assert.equal(await db.prepare("SELECT count(*) AS n FROM mcp_diagnostic_requests").first("n"), 0);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM mcp_transfers").first("n"), 0);
    assert.equal(content(await call("prepare_download", get), true).code, 404);

    const result = content(await call("run_diagnostic", diag), true);
    assert.deepEqual(result, {
      status: "failed", stdout: "", stderr: "", exitCode: null, signal: null,
      error: "An authenticated web SSH connection with a verified host key is required",
    });
    assert.equal(content(await call("run_diagnostic", diag), true).code, 409);
    assert.equal(content(await call("run_diagnostic", { ...diag, asJob: true }), true).status, "unknown");
    const jobArgs = { ...diag, asJob: true, requestId: randomUUID() };
    const job = { serverId, jobId: jobArgs.requestId };
    assert.equal(content(await call("run_diagnostic", jobArgs)).jobId, job.jobId);
    assert.equal(content(await call("run_diagnostic", jobArgs)).jobId, job.jobId);
    assert.equal(content(await call("run_diagnostic", { ...jobArgs, asJob: false }), true).code, 409);
    assert.equal(content(await call("run_diagnostic", { ...jobArgs, diagnostic: "check_exit" }), true).code, 409);
    for (const name of ["get_job_status", "read_job_output", "read_job_tail", "cancel_job"]) {
      assert.equal(content(await call(name, { ...job, serverId: "b" }), true).code, 403);
      assert.equal(content(await call(name, job)).jobId, job.jobId);
    }
    const stderrTail = { ...job, stream: "stderr" };
    assert.equal(content(await call("read_job_tail", { ...stderrTail, serverId: "b" }), true).code, 403);
    const other = await (await request(manager + "/tokens", "POST", webHeaders, {})).json();
    const otherResult = await (await rpc("tools/call", { name: "read_job_output", arguments: job },
      { Authorization: "Bearer " + other.token })).json();
    assert.equal(content(otherResult, true).code, 404);
    const otherTail = await (await rpc("tools/call", { name: "read_job_tail", arguments: stderrTail },
      { Authorization: "Bearer " + other.token })).json();
    assert.equal(content(otherTail, true).code, 404);
    await request(manager + "/tokens/" + other.id, "DELETE", webHeaders);
    await select("a"); // Regranting the same server starts a different authorization revision.
    assert.equal(content(await call("read_job_output", job), true).code, 404);
    assert.equal(content(await call("read_job_tail", stderrTail), true).code, 404);
    const ticket = content(await call("prepare_upload", put));
    assert.equal(ticket.status, "pending_local_io");
    assert.equal(ticket.bytes, 4);
    assert.equal(ticket.sha256, sha256);
    assert.notEqual(ticket.operationId, ticket.fileId);
    const endpoint = "/api/mcp-transfers/" + ticket.operationId;
    const headers = { Authorization: rpcHeaders.Authorization, "Content-Type": "application/octet-stream",
      "X-Content-SHA256": sha256 };
    const send = (auth) => raw(endpoint, { method: "PUT", headers: { ...headers, Authorization: auth }, body: bytes });
    assert.equal((await send(webHeaders.Authorization)).status, 401);
    const upload = await send(rpcHeaders.Authorization);
    assert.equal(upload.status, 422);
    assert.equal((await upload.json()).status, "failed");
    assert.equal((await send(rpcHeaders.Authorization)).status, 409);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM mcp_files").first("n"), 0);

    // A pre-existing managed record permits preparation. The GET still checks
    // the SSH host key before reading any remote bytes.
    const row = await db.prepare("SELECT version FROM mcp_target_identities WHERE server_id=?").bind(serverId).first();
    await db.prepare("INSERT INTO mcp_files (id,server_id,identity_version,storage_id,bytes,sha256) VALUES (?,?,?,?,?,?)")
      .bind(get.fileId, serverId, row.version, randomUUID(), 4, sha256).run();
    const readTicket = content(await call("prepare_download", get));
    assert.equal(readTicket.fileId, get.fileId);
    assert.equal(readTicket.sha256, sha256);
    const download = await request("/api/mcp-transfers/" + readTicket.operationId, "GET",
      { Authorization: rpcHeaders.Authorization });
    assert.equal(download.status, 422);
    assert.equal((await download.json()).status, "failed");
    assert.equal(connectionAttempts, 0);
  });
  assert.equal((await select("b")).status, 200);
  assert.deepEqual(await list(), [{ id: "b", name: "B" }]);
  assert.equal((await request(manager + "/authorization", "DELETE", webHeaders)).status, 200);
  assert.deepEqual(await list(), []);
  const afterEnd = await state();
  assert.equal(afterEnd.tokens.length, 1);
  assert.ok(!JSON.stringify(afterEnd).includes(pairing.token));
  assert.equal((await request(manager + "/tokens/" + pairing.id, "DELETE", webHeaders)).status, 200);
  assert.equal((await rpc("tools/list", {})).status, 401);
  assert.equal((await request(manager + "/tokens/" + pairing.id, "DELETE", webHeaders)).status, 404);
});

test("simulated Access JWT manages a pairing while its MCP token can only list its confirmed servers", async (t) => {
  const team = "access-fixture.invalid";
  const issuer = "https://" + team;
  const audience = randomUUID();
  const kid = randomUUID();
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid, alg: "RS256", use: "sig" };
  const fetched = [];
  const { request, db } = await localWorker(t, {
    bindings: { ACCESS_TEAM_DOMAIN: team, ACCESS_AUD: audience },
    outboundService(req) {
      fetched.push({ method: req.method, url: req.url });
      if (req.method === "GET" && req.url === issuer + "/cdn-cgi/access/certs") {
        return Response.json({ keys: [jwk] });
      }
      return new Response(null, { status: 403 });
    },
  });
  const assertion = (aud) => new SignJWT({})
    .setProtectedHeader({ alg: "RS256", kid }).setIssuer(issuer).setAudience(aud)
    .setSubject("test-owner").setIssuedAt().setExpirationTime("5m").sign(privateKey);
  const web = {
    Origin: origin, "Content-Type": "application/json", "Cf-Access-Jwt-Assertion": await assertion(audience),
  };
  assert.equal((await request(manager + "/state")).status, 401);
  assert.equal((await request(manager + "/tokens", "POST", {
    Origin: origin, "Content-Type": "application/json",
  }, {})).status, 401);
  assert.equal((await request(manager + "/state", "GET", {
    ...web, "Cf-Access-Jwt-Assertion": await assertion("wrong-audience"),
  })).status, 401);
  const creation = await request(manager + "/tokens", "POST", web, {});
  assert.equal(creation.status, 201);
  const pairing = await creation.json();
  await seedServers(db);
  const state = await (await request(manager + "/state", "GET", web)).json();
  const { id, identityVersion } = state.availableServers.find((s) => s.id === "a");
  assert.equal((await request(manager + "/authorization", "PUT", web, {
    revision: state.revision, servers: [{ id, identityVersion }],
  })).status, 200);

  const bearer = { Authorization: "Bearer " + pairing.token };
  const list = (auth) => request("/mcp", "POST", {
    "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...auth,
  }, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_authorized_servers" } });
  assert.equal((await list(web)).status, 401);
  const listed = await list(bearer);
  assert.equal(listed.status, 200);
  assert.deepEqual(JSON.parse((await listed.json()).result.content[0].text), { servers: [{ id: "a", name: "A" }] });
  assert.equal((await request(manager + "/state", "GET", bearer)).status, 401);
  assert.equal((await request("/api/v1/servers/a/credential", "GET", { ...web, ...bearer })).status, 401);
  assert.equal((await request(manager + "/tokens/" + pairing.id, "DELETE", web)).status, 200);
  assert.equal((await list(bearer)).status, 401);
  assert.ok(fetched.length > 0);
  assert.ok(fetched.every((r) => r.method === "GET" && r.url === issuer + "/cdn-cgi/access/certs"));
});
