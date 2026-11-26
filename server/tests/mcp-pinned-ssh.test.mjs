import assert from "node:assert/strict";
import test from "node:test";
import { executeFixedDiagnostic, isMcpDiagnostic, McpSshError } from "../src/lib/mcp-ssh.ts";
import { resolveHostAddress } from "../src/lib/resolve-host.ts";
import { ECDHKeyExchange } from "../src/ssh/kex-ecdh.ts";
import { SSHSession } from "../src/ssh/session.ts";
import {
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_DATA, SSH_MSG_KEX_ECDH_REPLY, SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_USERAUTH_FAILURE, SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_SUCCESS,
} from "../src/ssh/types.ts";
import { concat, encodeString, encodeUint32 } from "../src/ssh/utils.ts";

const byte = (n) => Uint8Array.of(n);
const config = { host: "example.invalid", port: 22, username: "fixture", password: "test-only" };
const sink = { send() {}, close() {} };

test("DNS falls back to a typed IPv6 record and cannot substitute a second hostname", async (t) => {
  const queries = [];
  t.mock.method(globalThis, "fetch", async (input) => {
    const query = new URL(input);
    assert.equal(query.origin, "https://1.1.1.1");
    assert.equal(query.searchParams.get("name"), "example.invalid");
    const type = query.searchParams.get("type");
    queries.push(type);
    return Response.json({ Status: 0, Answer: type === "A" ? [{ type: 1, data: "other.invalid" }]
      : [{ type: 28, data: "2001:db8::1" }] });
  });
  assert.equal(await resolveHostAddress("example.invalid"), "2001:db8::1");
  assert.deepEqual(queries, ["A", "AAAA"]);
});

async function keyExchange(t, { pin = "none", valid = true } = {}) {
  const signer = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const key = new Uint8Array(await crypto.subtle.exportKey("raw", signer.publicKey));
  const hostKey = concat(encodeString("ssh-ed25519"), encodeString(key));
  const fingerprint = "SHA256:" + Buffer.from(await crypto.subtle.digest("SHA-256", hostKey)).toString("base64").replace(/=+$/, "");
  const expectedFingerprint = pin === "match" ? fingerprint : pin === "wrong" ? "SHA256:" + "a".repeat(43) : undefined;
  const events = [];
  const session = new SSHSession(sink, sink, { ...config, expectedFingerprint },
    pin !== "none", false, undefined, pin !== "none", {
      beforeCredentials: async () => { events.push("rechecked"); },
      authenticated: (fp) => { events.push(fp); },
      closed: (failure) => { events.push(failure); },
    });
  t.after(() => session.close());
  session.startKeepalive = () => {};
  session.buildEncryptedPacket = async (payload) => payload;
  session.writeSocket = async (payload) => { events.push(payload[0]); };
  session.state = "kex";
  session.negotiatedKexAlgorithm = "ecdh-sha2-nistp256";
  session.negotiatedHostKeyAlgorithm = "ssh-ed25519";
  session.kexInitLocal = byte(20);
  session.kexInitRemote = byte(20);
  session.ecdhKeyPair = await ECDHKeyExchange.generateKeyPair();
  session.kexRawPublicKey = await ECDHKeyExchange.exportRawPublicKey(session.ecdhKeyPair);
  const peer = await ECDHKeyExchange.generateKeyPair();
  const serverPublic = await ECDHKeyExchange.exportRawPublicKey(peer);
  const shared = await ECDHKeyExchange.computeSharedSecret(peer.privateKey, session.kexRawPublicKey);
  const hash = await ECDHKeyExchange.computeExchangeHash(
    session.transport.getLocalVersion(), session.transport.getRemoteVersion(), session.kexInitLocal,
    session.kexInitRemote, hostKey, session.kexRawPublicKey, serverPublic, shared,
  );
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", signer.privateKey, hash));
  if (!valid) signature[0] ^= 1;
  await session.handlePacket({ payload: concat(byte(SSH_MSG_KEX_ECDH_REPLY), encodeString(hostKey),
    encodeString(serverPublic), encodeString(concat(encodeString("ssh-ed25519"), encodeString(signature)))) });
  const auth = async (success) => {
    assert.equal(session.state, "kex");
    session.state = "auth";
    await session.handlePacket({ payload: byte(SSH_MSG_SERVICE_ACCEPT) });
    await session.handlePacket({ payload: byte(success ? SSH_MSG_USERAUTH_SUCCESS : SSH_MSG_USERAUTH_FAILURE) });
  };
  return { session, events, fingerprint, auth };
}

test("a web key is observed only after a valid exchange signature and successful SSH user authentication", async (t) => {
  const accepted = await keyExchange(t);
  assert.deepEqual(accepted.events, []);
  await accepted.auth(true);
  assert.ok(accepted.events.includes(accepted.fingerprint));
  assert.ok(accepted.events.indexOf(SSH_MSG_USERAUTH_REQUEST) < accepted.events.indexOf(accepted.fingerprint));
  const denied = await keyExchange(t);
  await denied.auth(false);
  assert.ok(!denied.events.includes(denied.fingerprint));
  const invalid = await keyExchange(t, { valid: false });
  await invalid.auth(true);
  assert.ok(!invalid.events.includes(invalid.fingerprint));
});

test("pinned SSH rejects a changed key or an invalid signature before sending credentials", async (t) => {
  for (const options of [{ pin: "wrong" }, { pin: "match", valid: false }]) {
    const denied = await keyExchange(t, options);
    assert.deepEqual(denied.events, ["host_key"]);
    assert.equal(denied.session.isSSHReady(), false);
  }
  const accepted = await keyExchange(t, { pin: "match" });
  await accepted.auth(true);
  assert.ok(accepted.session.isSSHReady());
  assert.deepEqual(accepted.events, ["rechecked", SSH_MSG_USERAUTH_REQUEST, accepted.fingerprint]);
});

test("only fixed diagnostics are dispatched, and revocation while opening the channel prevents the request", async () => {
  const commands = [];
  const capture = { execCommand(command) { commands.push(command); } };
  for (const op of ["utc", "system_name", "check_exit"]) {
    assert.ok(isMcpDiagnostic(op));
    executeFixedDiagnostic(capture, op, async () => {});
  }
  assert.deepEqual(commands, ["/bin/date -u '+%Y-%m-%dT%H:%M:%SZ'", "/bin/uname -s",
    "printf '%s\\n' 'ternssh diagnostic' >&2; exit 1"]);
  for (const op of ["toString", "__proto__", "utc other", {}, null]) {
    assert.equal(isMcpDiagnostic(op), false);
    assert.throws(() => executeFixedDiagnostic(capture, op, async () => {}));
  }
  const session = new SSHSession(sink, sink, config, true, false, undefined, true);
  const sent = [];
  session.state = "ready";
  session.sendEncrypted = async (payload) => { sent.push(payload[0]); };
  const result = executeFixedDiagnostic(session, "utc", async () => { throw new Error("Grant replaced"); });
  const failed = assert.rejects(result, /Grant replaced/);
  await Promise.resolve();
  await session.handlePacket({ payload: concat(byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION),
    encodeUint32(0), encodeUint32(9), encodeUint32(65536), encodeUint32(32768)) });
  await failed;
  assert.ok(!sent.includes(SSH_MSG_CHANNEL_REQUEST));
});

test("an authenticated, pinned background connection opens an independent SFTP v3 subsystem", async (t) => {
  const { session, auth } = await keyExchange(t, { pin: "match" });
  await auth(true);
  const sent = [];
  session.sendEncrypted = async (payload) => { sent.push(payload); };
  const opened = session.openSftpClient();
  const channel = encodeUint32(0);
  const deliver = (type, ...parts) => session.handlePacket({ payload: concat(byte(type), channel, ...parts) });
  await deliver(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, encodeUint32(7), encodeUint32(65536), encodeUint32(32768));
  await deliver(SSH_MSG_CHANNEL_SUCCESS);
  // SFTP VERSION packet with negotiated version 3.
  await deliver(SSH_MSG_CHANNEL_DATA, encodeString(concat(encodeUint32(5), byte(2), encodeUint32(3))));
  const client = await opened;
  assert.equal(typeof client.readFile, "function");
  assert.ok(sent.some((payload) => payload[0] === SSH_MSG_CHANNEL_REQUEST &&
    Buffer.from(payload).includes(Buffer.from("sftp"))));
});

test("pre-dispatch exec and SFTP negotiation deadlines reach the gateway as typed timeouts", async (t) => {
  const { session, auth } = await keyExchange(t, { pin: "match" });
  await auth(true);
  session.sendEncrypted = async () => {};
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const typedTimeout = (error) => error instanceof McpSshError && error.timedOut === true;
  const opening = assert.rejects(session.openSftpClient(), typedTimeout);
  t.mock.timers.tick(15000);
  await opening;
  let dispatched = false;
  const running = assert.rejects(executeFixedDiagnostic(session, "utc", async () => { dispatched = true; }), typedTimeout);
  await Promise.resolve();
  t.mock.timers.tick(10000);
  await running;
  assert.equal(dispatched, false);
});
