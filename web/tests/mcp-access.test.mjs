import assert from "node:assert/strict";
import test from "node:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { inspectApprovalKey } from "../src/lib/mcp-approval-key.ts";
import { api, ApiResponseError } from "../src/lib/api.ts";
import { ADDABLE_WIDGETS } from "../src/dashboard/widgets.ts";
import {
  buildDashboardLayoutExport,
  layoutImportToDashboardWidgets,
  parseDashboardLayoutImport,
  serializeDashboardLayoutExport,
} from "../src/lib/dashboard-layout-io.ts";

const oldTypes = [
  "server_list", "terminal", "file_manager", "status", "network",
  "process", "container", "quick_commands", "ai_command",
];

function widget(type, config_json = null, index = 0) {
  return { type, config_json, grid_x: index, grid_y: index * 3, grid_w: 3, grid_h: 6 };
}

test("the optional MCP card preserves all nine old widgets and their layout round trip", () => {
  assert.deepEqual(ADDABLE_WIDGETS.map((item) => item.type), [...oldTypes, "mcp_access"]);
  const widgets = oldTypes.map((type, index) => widget(type, null, index));
  widgets[1].config_json = '{"fontSize":14}';
  widgets[7].config_json = '{"customCommands":[{"label":"Path","command":"pwd"}]}';
  const file = buildDashboardLayoutExport({ dashboard: { name: "Sample" }, widgets });
  const imported = parseDashboardLayoutImport(serializeDashboardLayoutExport(file));
  const saved = layoutImportToDashboardWidgets(imported).map(({ id, ...item }) => {
    assert.ok(id);
    return item;
  });
  assert.deepEqual(saved, widgets);
});

test("MCP layout round trips only its type and geometry, including forged imported widgets", () => {
  const fake = '{"authorizedServerIds":["forged"],"token":"example-secret"}';
  const record = widget("mcp_access", fake);
  const file = buildDashboardLayoutExport({ dashboard: { name: "Sample" }, widgets: [record] });
  assert.deepEqual(file.widgets, [widget("mcp_access")]);
  const forged = { ...file, widgets: [{ ...record, tokens: ["wrong"] }] };
  const imported = parseDashboardLayoutImport(JSON.stringify(forged));
  const [{ id, ...saved }] = layoutImportToDashboardWidgets(imported);
  assert.ok(id);
  assert.deepEqual(saved, widget("mcp_access"));
  assert.equal(record.config_json, fake);
});

test("unmigrated AI keys never leave the dashboard in a layout export", () => {
  const preferences = { model: "demo", apiBaseUrl: "https://example.com/v1" };
  const original = widget("ai_command", JSON.stringify({ ...preferences, apiKey: "fake-marker" }));
  const file = buildDashboardLayoutExport({ dashboard: { name: "Sample" }, widgets: [original] });
  assert.deepEqual(JSON.parse(file.widgets[0].config_json), preferences);
  assert.ok(!serializeDashboardLayoutExport(file).includes("fake-marker"));
  assert.ok(original.config_json.includes("fake-marker"));
  for (const config of ['{bad fake-marker', '{"apiBaseUrl":"https://example.com/?key=fake-marker"}']) {
    const exported = buildDashboardLayoutExport({
      dashboard: { name: "Sample" }, widgets: [widget("ai_command", config)],
    });
    assert.ok(!serializeDashboardLayoutExport(exported).includes("fake-marker"));
  }
});

test("management requests use the website routes, send whole selections, and never retry a write", async (t) => {
  const requests = [];
  t.mock.method(globalThis, "fetch", async (path, options) => {
    requests.push({ path, method: options.method ?? "GET", body: options.body });
    if (options.method === "PUT") return Response.json({ error: "Changed" }, { status: 409 });
    return Response.json({ ok: true });
  });
  await api.getMcpAccess(new AbortController().signal);
  const choice = { id: "test-A", identityVersion: "version-A", workspaceShell: true };
  await assert.rejects(api.replaceMcpAuthorization(11, [choice]),
    (error) => error instanceof ApiResponseError && error.status === 409);
  await api.endMcpAuthorization();
  await api.issueMcpToken();
  await api.registerMcpApprovalKey("selected/id", "public-fixture");
  await api.revokeMcpToken("token/id");
  assert.deepEqual(requests, [
    { path: "/api/v1/mcp-access/state", method: "GET", body: undefined },
    { path: "/api/v1/mcp-access/authorization", method: "PUT", body: JSON.stringify({ revision: 11, servers: [choice] }) },
    { path: "/api/v1/mcp-access/authorization", method: "DELETE", body: undefined },
    { path: "/api/v1/mcp-access/tokens", method: "POST", body: "{}" },
    { path: "/api/v1/mcp-access/tokens/selected%2Fid/approval-key", method: "POST", body: JSON.stringify({ publicKeySpki: "public-fixture" }) },
    { path: "/api/v1/mcp-access/tokens/token%2Fid", method: "DELETE", body: undefined },
  ]);
});

test("enrollment displays SHA-256 of the selected P-256 public key and rejects other inputs", async () => {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = pair.publicKey.export({ type: "spki", format: "der" });
  const spki = der.toString("base64");
  const inspected = await inspectApprovalKey("  " + spki + "\n");
  assert.equal(inspected.publicKeySpki, spki);
  assert.equal(inspected.fingerprint, createHash("sha256").update(der).digest("hex"));
  await assert.rejects(inspectApprovalKey(spki.replace(/=+$/, "")));
  const alternate = generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey;
  await assert.rejects(inspectApprovalKey(alternate.export({ type: "spki", format: "der" }).toString("base64")));
  const invalidPoint = Buffer.from(der);
  invalidPoint.fill(0, invalidPoint.length - 64);
  await assert.rejects(inspectApprovalKey(invalidPoint.toString("base64")));
});
