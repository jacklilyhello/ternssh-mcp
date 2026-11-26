import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const cli = fileURLToPath(new URL("./mcp-transfer.mjs", import.meta.url));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const limit = 1024 * 1024;

test("local transfer CLI against a paired, in-memory HTTPS gateway", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "ternssh-cli-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const cert = join(dir, "ca.crt");
  const key = join(dir, "key.pem");
  await exec("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=ternssh-transfer-fixture", "-addext", "subjectAltName=IP:127.0.0.1",
    "-keyout", key, "-out", cert]);
  const token = "tmcp_" + randomBytes(32).toString("base64url");
  const operations = new Map();
  const calls = [];
  const serverErrors = [];
  const gateway = https.createServer({ key: await readFile(key), cert: await readFile(cert) }, (req, res) => {
    const id = req.url.split("/").at(-1);
    calls.push(req.url);
    if (req.headers.authorization !== "Bearer " + token || req.url !== "/api/mcp-transfers/" + id ||
        !operations.has(id)) {
      res.writeHead(403).end();
      return;
    }
    Promise.resolve().then(() => operations.get(id)(req, res)).catch(() => {
      serverErrors.push("The mocked gateway rejected an unexpected request.");
      res.destroy();
    });
  });
  gateway.listen(0, "127.0.0.1");
  await once(gateway, "listening");
  t.after(() => new Promise((resolve) => gateway.close(resolve)));
  const origin = "https://127.0.0.1:" + gateway.address().port;

  function operation(handler) {
    const id = randomUUID();
    operations.set(id, handler);
    return id;
  }
  async function run(direction, id, file, extra = [], pairedOrigin = origin) {
    const args = [cli, direction, "--operation", id, "--file", file, ...extra];
    const env = { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: cert,
      TERNSSH_MCP_TOKEN: token };
    if (pairedOrigin !== null) env.TERNSSH_MCP_ORIGIN = pairedOrigin;
    let output, code;
    try {
      output = await exec(process.execPath, args, { env });
      code = 0;
    } catch (error) {
      output = error;
      code = error.code;
    }
    assert.ok(!output.stdout.includes(token) && !output.stderr.includes(token));
    return { code, result: JSON.parse(code === 0 ? output.stdout : output.stderr) };
  }
  function downloadReply(body, digest = hash(body)) {
    return operation((_req, res) => res.writeHead(200, { "X-Content-SHA256": digest }).end(body));
  }
  async function checkNoStagingFiles() {
    assert.ok(!(await readdir(dir)).some((file) => file.startsWith(".ternssh-part-")));
  }

  await t.test("text, arbitrary binary, and exactly 1 MiB reach disk with verified lengths and hashes", async () => {
    for (const [index, bytes] of [Buffer.from("Example\n二进制\n"), Buffer.from([0, 1, 255, 0, 52]),
      Buffer.alloc(0), randomBytes(limit)].entries()) {
      const local = join(dir, "source-" + index);
      const dest = join(dir, "saved-" + index);
      const fileId = randomUUID();
      let stored;
      const put = operation(async (req, res) => {
        assert.equal(req.method, "PUT");
        assert.equal(req.headers["content-type"], "application/octet-stream");
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        stored = Buffer.concat(chunks);
        assert.equal(req.headers["x-content-sha256"], hash(stored));
        res.writeHead(201).end(JSON.stringify({ fileId, bytes: stored.length, sha256: hash(stored) }));
      });
      await writeFile(local, bytes);
      const upload = await run("upload", put, local);
      assert.deepEqual(upload.result, { status: "uploaded", fileId, file: local, bytes: bytes.length, sha256: hash(bytes) });
      const download = await run("download", downloadReply(stored), dest);
      assert.deepEqual(download.result, { status: "saved", file: dest, bytes: bytes.length, sha256: hash(bytes) });
      const actual = await readFile(dest);
      assert.equal(actual.length, bytes.length);
      assert.equal(hash(actual), hash(bytes));
    }
  });

  await t.test("default no-clobber including races, explicit local replacement, and symlinks", async () => {
    const dest = join(dir, "owned");
    const original = Buffer.from("original");
    const replacement = Buffer.from("replacement");
    await writeFile(dest, original);
    const reply = downloadReply(replacement);
    const before = calls.length;
    assert.equal((await run("download", reply, dest)).code, 1);
    assert.equal(calls.length, before);
    assert.deepEqual(await readFile(dest), original);
    assert.equal((await run("download", reply, dest, ["--overwrite"])).code, 0);
    assert.deepEqual(await readFile(dest), replacement);
    const racer = join(dir, "racer");
    const race = operation(async (_req, res) => {
      await writeFile(racer, original, { flag: "wx" });
      res.writeHead(200, { "X-Content-SHA256": hash(replacement) }).end(replacement);
    });
    assert.equal((await run("download", race, racer)).code, 1);
    assert.deepEqual(await readFile(racer), original);
    const alias = join(dir, "alias");
    await symlink(racer, alias);
    assert.equal((await run("download", reply, alias, ["--overwrite"])).code, 1);
    assert.deepEqual(await readFile(racer), original);
    await checkNoStagingFiles();
  });

  await t.test("interruption, wrong/missing hash, revoked grants, and oversized chunked responses preserve the destination", async () => {
    const dest = join(dir, "preserved");
    await writeFile(dest, "original");
    const corrupt = [
      operation((_req, res) => { res.writeHead(200, { "Content-Length": 100 }); res.write("short"); res.destroy(); }),
      downloadReply(Buffer.from("changed"), hash(Buffer.from("original"))),
      operation((_req, res) => res.writeHead(200).end("missing digest")),
      operation((_req, res) => res.writeHead(403).end("untrusted error text")),
      operation((_req, res) => {
        res.writeHead(200, { "X-Content-SHA256": hash(Buffer.alloc(0)) });
        res.write(Buffer.alloc(limit)); res.end("extra byte");
      }),
    ];
    for (const id of corrupt) {
      const before = calls.length;
      const got = await run("download", id, dest, ["--overwrite"]);
      assert.equal(got.code, 1);
      assert.equal(got.result.status, "failed");
      assert.ok(!got.result.message.includes("untrusted error text"));
      assert.equal(calls.length, before + 1);
      assert.equal(await readFile(dest, "utf8"), "original");
      await checkNoStagingFiles();
    }
  });

  await t.test("lost or invalid upload acknowledgments are unknown and never replayed", async () => {
    const file = join(dir, "source-0");
    for (const handle of [
      (_req, res) => res.destroy(),
      (_req, res) => res.writeHead(503).end("untrusted"),
      (_req, res) => res.writeHead(409).end("already used"),
      (_req, res) => res.writeHead(200).end("{}"),
      (_req, res) => res.writeHead(200).end("not json"),
    ]) {
      const before = calls.length;
      const got = await run("upload", operation(handle), file);
      assert.equal(got.code, 1);
      assert.equal(got.result.status, "unknown");
      assert.equal(calls.length, before + 1);
    }
  });

  await t.test("oversized uploads, off-origin options and redirects cannot forward the bearer", async () => {
    const large = join(dir, "too-large");
    await writeFile(large, Buffer.alloc(limit + 1));
    const before = calls.length;
    const redirect = operation((_req, res) => res.writeHead(307, { Location: origin + "/trap" }).end());
    assert.equal((await run("upload", redirect, large)).code, 1);
    const unconfigured = await run("upload", redirect, join(dir, "source-0"), ["--origin", origin], null);
    assert.equal(unconfigured.code, 1);
    assert.match(unconfigured.result.message, /TERNSSH_MCP_ORIGIN/);
    for (const unpaired of ["https://127.0.0.1:1", "http://127.0.0.1", origin + "/other"]) {
      assert.equal((await run("upload", redirect, join(dir, "source-0"), ["--origin", unpaired])).code, 1);
    }
    assert.equal(calls.length, before);
    const got = await run("upload", redirect, join(dir, "source-0"), ["--origin", origin]);
    assert.equal(got.code, 1);
    assert.equal(calls.length, before + 1);
    assert.ok(!calls.includes("/trap"));
    let trapHits = 0;
    const trap = https.createServer({ key: await readFile(key), cert: await readFile(cert) }, (_req, res) => {
      trapHits++;
      res.writeHead(403).end();
    });
    trap.listen(0, "127.0.0.1");
    await once(trap, "listening");
    try {
      const elsewhere = operation((_req, res) => res.writeHead(307, {
        Location: "https://127.0.0.1:" + trap.address().port + "/trap",
      }).end());
      assert.equal((await run("upload", elsewhere, join(dir, "source-0"))).code, 1);
      assert.equal((await run("download", elsewhere, join(dir, "redirected-download"))).code, 1);
      assert.equal(trapHits, 0);
    } finally {
      await new Promise((resolve) => trap.close(resolve));
    }
  });
  assert.deepEqual(serverErrors, []);
});
