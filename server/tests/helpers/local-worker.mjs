import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { unstable_splitSqlQuery as statements } from "wrangler";

const origin = "https://ternssh.example";

export async function localWorker(t, options = {}, buildPlugins = []) {
  const source = await build({
    entryPoints: [fileURLToPath(new URL("../../src/index.ts", import.meta.url))],
    plugins: buildPlugins, bundle: true, format: "esm", write: false, platform: "browser", external: ["cloudflare:*"],
  });
  const mf = new Miniflare({
    modules: true, script: source.outputFiles[0].text, compatibilityDate: "2026-01-01",
    compatibilityFlags: ["nodejs_compat", "enable_request_signal"], d1Databases: ["DB"], cf: false,
    serviceBindings: { ASSETS: () => new Response("web assets") },
    outboundService: () => new Response(null, { status: 403 }),
    ...options,
  });
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("DB");
  const migrations = new URL("../../migrations/", import.meta.url);
  for (const file of (await readdir(migrations)).filter((f) => f.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(file, migrations), "utf8");
    await db.batch(statements(sql).map((s) => db.prepare(s)));
  }

  const request = (path, method = "GET", headers = {}, data) => mf.dispatchFetch(origin + path, {
    method, headers, body: data === undefined ? undefined : JSON.stringify(data),
  });
  const raw = (path, init) => mf.dispatchFetch(origin + path, init);
  return { request, raw, db, address: await mf.ready };
}
