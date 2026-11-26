import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { McpJobOutput } from "../src/lib/mcp-job-output.ts";
import { validateWorkspaceCommand, workspaceShellCommand } from "../src/lib/mcp-workspace.ts";
import { jobStorage } from "./helpers/job-storage.mjs";

test("workspace input preserves UTF-8 shell text and refuses unrepresentable inputs", () => {
  const text = "printf '%s\\n' '中文'\n";
  assert.equal(validateWorkspaceCommand(text), text);
  assert.equal(validateWorkspaceCommand("x".repeat(4096)).length, 4096);
  for (const invalid of [null, {}, "", " ", "\u0000", "a\ud800b"]) {
    assert.throws(() => validateWorkspaceCommand(invalid), error => error.status === 400);
  }
  assert.throws(() => validateWorkspaceCommand("中".repeat(1366)), error => error.status === 413);
  assert.throws(() => workspaceShellCommand(text, 999), error => error.status === 400);
  assert.throws(() => workspaceShellCommand(text, 600001), error => error.status === 400);
  const launch = workspaceShellCommand(text, 1000);
  assert.ok(!launch.includes(text));
  assert.ok(launch.includes(Buffer.from(text).toString("base64")));
});

test("preinstalled runtime alternatives preserve isolation and missing or unsafe candidates fail closed", {
  skip: process.env.TERNSSH_WORKSPACE_CI !== "1", timeout: 120_000,
}, t => {
  const fixture = mkdtempSync(join(tmpdir(), "ternssh-runtime-layout-"));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  // On the Ubuntu CI runner /bin aliases /usr/bin. All package-layout changes
  // below happen in a private mount namespace with an ephemeral upper layer.
  const mountFixture = [
    "set -eu", "umask 022",
    'fixture=$1; export fixture',
    'mount -t tmpfs -o mode=0755,size=32M tmpfs "$fixture"',
    'mkdir "$fixture/lower" "$fixture/upper" "$fixture/work" "$fixture/decoy"',
    'mount --bind /usr "$fixture/lower"',
    'mount -t overlay overlay -o "lowerdir=$fixture/lower,upperdir=$fixture/upper,workdir=$fixture/work" /usr',
    'test "$(findmnt -n -o FSTYPE --target /usr)" = overlay',
    'test /bin -ef /usr/bin',
    'mkdir -p /usr/libexec',
    'rm -f /usr/bin/bwrap /usr/bin/busybox /usr/bin/busybox.static /usr/libexec/flatpak-bwrap',
    '/bin/sh -eu -c "$2"',
    'PATH="$fixture/decoy:$PATH" /bin/sh -c "$3"',
  ].join("\n");
  const sentinel = "a-workspace-shell-was-started";
  function inFixture(setup, launch) {
    const child = spawnSync("/usr/bin/sudo", ["-n", "--", "/usr/bin/unshare", "--mount", "--propagation", "private",
      "--", "/bin/sh", "-c", mountFixture, "fixture", fixture, setup, launch], {
      encoding: "utf8", timeout: 18_000, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 20,
    });
    assert.ifError(child.error);
    return child;
  }
  function run(setup, command = `printf '%s' '${sentinel}'`) {
    return inFixture(setup, workspaceShellCommand(command, 12000));
  }
  function refused(child, reason, bwrap, busybox, cgroup = "present") {
    assert.equal(child.status, 125, child.stderr.slice(0, 500));
    assert.equal(child.stdout, "");
    const lines = child.stderr.trimEnd().split("\n");
    assert.equal(lines.length, 2, child.stderr.slice(0, 500));
    assert.equal(lines[0], `ternssh: isolated workspace unavailable (${reason})`);
    // Only fixed prerequisite names and states may appear on the wire.
    const arch = { x64: "x86_64", arm64: "aarch64" }[process.arch];
    assert.ok(arch);
    assert.equal(lines[1], `ternssh: prerequisites v1 python3=ok systemd_run=present timeout=present arch=${arch} ` +
      `bwrap=${bwrap} busybox=${busybox} libseccomp=loadable cgroup_v2=${cgroup} scope=unverified namespaces=unverified`);
  }

  const missing = run([
    'install -m 0755 "$fixture/lower/bin/bwrap" "$fixture/decoy/bwrap"',
    'install -m 0755 "$fixture/lower/bin/busybox" "$fixture/decoy/busybox"',
  ].join("\n"));
  refused(missing, "missing_bwrap", "missing", "missing");
  const output = new McpJobOutput(jobStorage(t));
  output.append("stderr", Buffer.from(missing.stderr));
  const first = output.read(0, missing.stderr.indexOf("\n") + 1);
  const rest = output.read(first.nextCursor);
  assert.ok(first.hasMore && !rest.hasMore);
  assert.equal(rest.stdoutBytes, 0);
  assert.equal(rest.nextCursor, Buffer.byteLength(missing.stderr));
  assert.equal([...first.frames, ...rest.frames].map(f => f.text).join(""), missing.stderr);
  assert.equal(output.tail(rest.nextCursor - first.nextCursor).frames.map(f => f.text).join(""), rest.frames.map(f => f.text).join(""));

  refused(run([
    'install -m 0777 "$fixture/lower/bin/bwrap" /usr/bin/bwrap',
    'install -m 0755 /usr/bin/true /usr/bin/busybox.static',
  ].join("\n")), "unusable_bwrap", "unsafe", "incompatible");

  refused(run([
    'install -m 0755 "$fixture/lower/bin/bwrap" /usr/libexec/flatpak-bwrap',
    'chmod 0777 /usr/libexec',
    'install -o 65534 -m 0755 "$fixture/lower/bin/busybox" /usr/bin/busybox',
  ].join("\n")), "unusable_bwrap", "unsafe", "unsafe");

  refused(run([
    'ln -s "$fixture/lower/bin/bwrap" /usr/bin/bwrap',
    'install -m 4755 "$fixture/lower/bin/busybox" /usr/bin/busybox.static',
  ].join("\n")), "unusable_bwrap", "unsafe", "unsafe");

  // Hide only the fixture's view of the hierarchy, leaving the runner's
  // controllers and every real unit untouched.
  refused(run([
    'install -m 0755 "$fixture/lower/bin/bwrap" /usr/bin/bwrap',
    'install -m 0755 "$fixture/lower/bin/busybox" /usr/bin/busybox',
    'mount -t tmpfs -o ro,nosuid,nodev,noexec,size=4K tmpfs /sys/fs/cgroup',
    'test ! -e /sys/fs/cgroup/cgroup.controllers',
  ].join("\n")), "resource_scope_unavailable", "ready", "ready", "missing");

  const missingInterpreter = run([
    'rm /usr/bin/python3 /usr/bin/timeout',
    'ln -s /no-such-executable /usr/libexec/flatpak-bwrap',
  ].join("\n"));
  assert.equal(missingInterpreter.status, 125);
  assert.equal(missingInterpreter.stdout, "");
  assert.equal(missingInterpreter.stderr, "ternssh: isolated workspace unavailable (missing_static_busybox)\n" +
    "ternssh: prerequisites v1 python3=missing systemd_run=present timeout=missing arch=unverified " +
    "bwrap=unverified busybox=missing libseccomp=unverified cgroup_v2=present scope=unverified namespaces=unverified\n");

  const confined = [
    "set -e", 'test "$(id -u)" = 65534', 'test "$(pwd)" = /work',
    "test ! -e /etc/passwd", "test ! -e /proc/self",
    "printf 'isolated alternate\\n' | cat",
    "if /bin/busybox nc -l -p 31234; then exit 91; fi", "exit 37",
  ].join("\n");
  function assertConfined(result) {
    assert.equal(result.status, 37, result.stderr.slice(0, 500));
    assert.equal(result.stdout, "isolated alternate\n");
    assert.match(result.stderr, /socket.*(Function not implemented|Operation not permitted)/i);
  }
  const alternateBusyBox = 'install -m 0755 "$fixture/lower/bin/busybox" /usr/bin/busybox.static';
  assertConfined(run([
    'install -m 0755 "$fixture/lower/bin/bwrap" /usr/bin/bwrap',
    'install -m 0777 "$fixture/lower/bin/busybox" /usr/bin/busybox',
    alternateBusyBox,
  ].join("\n"), confined));

  const alternateBwrap = 'install -m 0755 "$fixture/lower/bin/bwrap" /usr/libexec/flatpak-bwrap';
  refused(run(alternateBwrap), "missing_static_busybox", "ready", "missing");
  const onlyAlternates = [alternateBwrap, alternateBusyBox].join("\n");
  const result = run(onlyAlternates, confined);
  if (result.status === 37) {
    assertConfined(result);
  } else {
    // Some hosted images permit user namespaces only for specific executable
    // paths. Independently confirm this same binary is denied on this image.
    const policy = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
    assert.ok(existsSync(policy) && readFileSync(policy, "utf8").trim() === "1", result.stderr);
    const probe = inFixture(onlyAlternates, [
      "/usr/bin/setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs",
      "/usr/libexec/flatpak-bwrap --unshare-user --unshare-pid --unshare-net --uid 65534 --gid 65534",
      "--new-session --die-with-parent --cap-drop ALL --ro-bind /usr/bin/busybox.static /bin/busybox",
      "-- /bin/busybox true",
    ].join(" "));
    assert.equal(probe.status, 1, probe.stderr);
    assert.match(probe.stderr, /^(?:flatpak-)?bwrap: (?:Creating new namespace failed|setting up (?:uid|gid) map|loopback: Failed RTM_NEWADDR): (?:Permission denied|Operation not permitted)\s*$/i);
    assert.equal(result.status, probe.status, result.stderr);
    assert.equal(result.stderr.trim(), probe.stderr.trim());
    assert.equal(result.stdout, "");
    t.diagnostic("Trusted flatpak-bwrap selected, then blocked by the runner's user namespace policy in both launches");
  }
});

// Use a genuine, disposable systemd scope and kernel namespaces on the hosted
// Linux runner. A missing prerequisite fails this CI check. No real SSH server,
// cloud credential, user data or host configuration change is involved.
test("Linux enforces the workspace boundary and keeps both output streams and shell status", {
  skip: process.env.TERNSSH_WORKSPACE_CI !== "1", timeout: 60_000,
}, async t => {
  function run(command, time = 12000) {
    const child = spawnSync("/usr/bin/sudo", ["-n", "--", "/bin/sh", "-c", workspaceShellCommand(command, time)], {
      encoding: "utf8", timeout: time + 4000, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 20,
    });
    assert.ifError(child.error);
    return child;
  }

  const outside = mkdtempSync(join(tmpdir(), "ternssh-kernel-fixture-"));
  t.after(() => rmSync(outside, { recursive: true, force: true }));
  const restriction = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
  const usernsRestriction = existsSync(restriction) ? readFileSync(restriction, "utf8").trim() : "unavailable";
  t.diagnostic(`Hosted runner AppArmor unprivileged user namespace restriction = ${usernsRestriction}`);
  const marker = randomUUID();
  const check = run([
    "set -e",
    "test \"$(pwd)\" = /work",
    "test \"$(id -u)\" = 65534",
    "test \"$(id -g)\" = 65534",
    "test ! -e /etc/passwd",
    "test ! -e /root",
    "test ! -e /proc/self",
    "test ! -e /sys",
    `test ! -e '${outside}'`,
    "uptime >/dev/null",
    `printf '%s\\n' '中文 ${marker}' | awk '{print $1}' > saved`,
    "cat saved",
    "printf 'synthetic tail' >&2",
    "exit 37",
  ].join("\n"));
  assert.equal(check.status, 37, check.stderr.slice(0, 500));
  assert.equal(check.stdout, "中文\n");
  assert.equal(check.stderr, "synthetic tail");
  // The confined command cannot create this path in the outer filesystem.
  const write = run(`echo restricted > '${outside}/marker'`);
  assert.notEqual(write.status, 0);
  assert.equal(existsSync(join(outside, "marker")), false);
  const fresh = run("test ! -e /work/saved && echo fresh");
  assert.equal(fresh.status, 0, fresh.stderr);
  assert.equal(fresh.stdout, "fresh\n");

  // An ordinary loopback listener must fail at socket creation. A network
  // namespace alone would still permit listening inside the namespace.
  const net = run("/bin/busybox nc -l -p 31234");
  assert.notEqual(net.status, 0);
  assert.match(net.stderr, /socket.*(Function not implemented|Operation not permitted)/i);
  // Name only this fixture's transient scope so the test can examine its
  // membership before and after the deadline without listing other processes.
  const unit = `ternssh-ci-${randomUUID()}.scope`;
  const launch = workspaceShellCommand("sleep 30 & echo ready; wait", 6000);
  const systemdRun = '/usr/bin/systemd-run "$@" --scope ';
  assert.ok(launch.includes(systemdRun));
  const named = launch.replace(systemdRun, `${systemdRun}--unit=${unit} `);
  const fixture = spawn("/usr/bin/sudo", ["-n", "--", "/bin/sh", "-c", named], {
    stdio: ["ignore", "pipe", "pipe"], timeout: 15000,
  });
  let ready = "";
  fixture.stdout.on("data", chunk => { ready += chunk.toString("utf8"); });
  fixture.stderr.resume();
  const closed = once(fixture, "close");
  try {
    const until = Date.now() + 6000;
    while (!ready.includes("ready\n") && fixture.exitCode === null && Date.now() < until) await delay(50);
    assert.equal(ready, "ready\n", "Background sleep did not reach its fixture scope");
    const group = spawnSync("/usr/bin/systemctl", ["show", unit, "-p", "ControlGroup", "--value"], { encoding: "utf8" });
    assert.ifError(group.error);
    assert.equal(group.status, 0);
    const path = group.stdout.trim();
    assert.ok(path.startsWith("/") && path.endsWith("/" + unit));
    const events = join("/sys/fs/cgroup", path.slice(1), "cgroup.events");
    assert.match(readFileSync(events, "utf8"), /^populated 1$/m);
    const [status] = await closed;
    assert.ok([124, 137].includes(status), "Expected the remote deadline to stop the workload");
    const cleanupDeadline = Date.now() + 3000;
    while (true) {
      try {
        if (/^populated 0$/m.test(readFileSync(events, "utf8"))) break;
      } catch (error) {
        if (error.code === "ENOENT") break;
        throw error;
      }
      assert.ok(Date.now() < cleanupDeadline, "Background processes remained in the fixture scope");
      await delay(50);
    }
  } finally {
    await closed;
  }
});
