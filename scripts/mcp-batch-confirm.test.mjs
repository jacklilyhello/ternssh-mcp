import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { approvalBridge } from "./mcp-batch-confirm.mjs";

test("the local confirmation tool accepts only a frozen batch reference", async () => {
  const dispatch = approvalBridge();
  const call = (method, params) => dispatch({jsonrpc:"2.0",id:1,method,params});
  assert.equal((await call("initialize", {protocolVersion:"2025-11-25"})).result.protocolVersion, "2025-11-25");
  const [tool] = (await call("tools/list", {})).result.tools;
  assert.equal(tool.annotations.readOnlyHint, false);
  assert.equal(tool.annotations.destructiveHint, true);
  assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), ["batchId","serverId"]);
  const ref = { serverId:"fixture", batchId:randomUUID() };
  for (const extra of [{signature:"opaque"},{command:"fixture"},{signer:"another"},{confirmed:true},{digest:"abc"},
    {batchId:"unbound"},{serverId:"invalid\nvalue"}]) {
    assert.equal((await call("tools/call",{name:tool.name,arguments:{...ref,...extra}})).error.code,-32602);
  }
});
