import assert from "node:assert/strict";
import test from "node:test";
import { SSHSession } from "../src/ssh/session.ts";
import {
  SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_REQUEST,
  SSH_MSG_DISCONNECT,
} from "../src/ssh/types.ts";
import { concat, encodeString, encodeUint32 } from "../src/ssh/utils.ts";

const byte = (value) => Uint8Array.of(value);
const channelId = encodeUint32(0);
const status = (code) => [encodeString("exit-status"), byte(0), encodeUint32(code)];

// Inject decrypted SSH packets at the session dispatcher; no network or host is involved.
async function execFixture(timeoutMs = 5000, outputLimit, sink, command = "fixture") {
  const session = new SSHSession({ send() {}, close() {} }, { close() {} }, {
    host: "synthetic.invalid", port: 22, username: "fixture", password: "",
  }, true, false, undefined, true);
  session.state = "ready";
  const sent = [];
  const payloads = [];
  session.sendEncrypted = async (payload) => { sent.push(payload[0]); payloads.push(payload); };
  const packet = (type, ...fields) => session.handlePacket({
    payload: concat(byte(type), channelId, ...fields),
  });
  const result = session.execCommand(command, timeoutMs, undefined, outputLimit, sink);
  const outcome = result.catch((error) => error);
  await Promise.resolve();
  await packet(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, encodeUint32(17), encodeUint32(65536), encodeUint32(32768));
  return { packet, sent, result, outcome, payloads };
}

test("a non-interactive streamed exec sends the command bytes verbatim and delivers output before completion", async () => {
  const input = "printf '%s\\n' '中文 value' | wc -c";
  const chunks = [];
  const { packet, payloads, result } = await execFixture(5000, undefined,
    (stream, bytes) => chunks.push([stream, Buffer.from(bytes)]), input);
  const execRequest = payloads.find(payload => payload[0] === SSH_MSG_CHANNEL_REQUEST);
  assert.deepEqual(Buffer.from(execRequest.subarray(18)), Buffer.from(input));
  assert.ok(payloads.some(payload => payload[0] === SSH_MSG_CHANNEL_EOF));
  const bytes = Buffer.from("中文");
  await packet(SSH_MSG_CHANNEL_DATA, encodeString(bytes.subarray(0, 2)));
  await packet(SSH_MSG_CHANNEL_EXTENDED_DATA, encodeUint32(1), encodeString("E"));
  await packet(SSH_MSG_CHANNEL_DATA, encodeString(bytes.subarray(2)));
  assert.deepEqual(chunks, [["stdout", bytes.subarray(0, 2)], ["stderr", Buffer.from("E")], ["stdout", bytes.subarray(2)]]);
  await packet(SSH_MSG_CHANNEL_REQUEST, ...status(17));
  await packet(SSH_MSG_CHANNEL_CLOSE);
  assert.deepEqual(await result, { stdout: "", stderr: "", exitCode: 17 });
});

test("exit-status can precede tail data, and stdout and stderr are complete when CLOSE arrives", async () => {
  const { packet, sent, result } = await execFixture();
  await packet(SSH_MSG_CHANNEL_DATA, encodeString("first "));
  await packet(SSH_MSG_CHANNEL_REQUEST, ...status(37));
  await packet(SSH_MSG_CHANNEL_DATA, encodeString("last"));
  await packet(SSH_MSG_CHANNEL_EXTENDED_DATA, encodeUint32(1), encodeString("tail error"));
  await packet(SSH_MSG_CHANNEL_EXTENDED_DATA, encodeUint32(99), encodeString("unrelated extension"));
  await packet(SSH_MSG_CHANNEL_CLOSE);
  assert.deepEqual(await result, { stdout: "first last", stderr: "tail error", exitCode: 37 });
  assert.equal(sent.filter((type) => type === SSH_MSG_CHANNEL_REQUEST).length, 1);
  assert.equal(sent.filter((type) => type === SSH_MSG_CHANNEL_CLOSE).length, 1);
});

test("EOF before exit-status waits for the numeric exit status", async () => {
  const { packet, result } = await execFixture();
  await packet(SSH_MSG_CHANNEL_EOF);
  await packet(SSH_MSG_CHANNEL_REQUEST, ...status(0));
  assert.deepEqual(await result, { stdout: "", stderr: "", exitCode: 0 });
});

test("CLOSE without a complete exit status returns unknown and keeps partial output", async () => {
  const { packet, outcome } = await execFixture();
  await packet(SSH_MSG_CHANNEL_REQUEST, encodeString("exit-status"), byte(0));
  await packet(SSH_MSG_CHANNEL_DATA, encodeString("partial"));
  await packet(SSH_MSG_CHANNEL_EOF);
  await packet(SSH_MSG_CHANNEL_CLOSE);
  const error = await outcome;
  assert.match(error.message, /结果未知/);
  assert.equal(error.exitCode, null);
  assert.equal(error.outputEnded, true);
  assert.equal(error.stdout, "partial");
});

test("a shared output bound preserves both stream prefixes and a previously reported exit status", async () => {
  for (const known of [true, false]) {
    const { packet, outcome, sent } = await execFixture(5000, 6);
    if (known) await packet(SSH_MSG_CHANNEL_REQUEST, ...status(0));
    await packet(SSH_MSG_CHANNEL_DATA, encodeString("abc"));
    await packet(SSH_MSG_CHANNEL_EXTENDED_DATA, encodeUint32(1), encodeString("defg"));
    const error = await outcome;
    assert.equal(error.outputTruncated, true);
    assert.equal(error.stdout, "abc");
    assert.equal(error.stderr, "def");
    assert.equal(error.exitCode, known ? 0 : null);
    assert.match(error.message, known ? /输出可能不完整/ : /结果未知/);
    assert.equal(sent.filter((type) => type === SSH_MSG_CHANNEL_REQUEST).length, 1);
  }
});

test("signal termination keeps its SSH name and trailing output without inventing a numeric exit code", async () => {
  const { packet, outcome } = await execFixture();
  await packet(SSH_MSG_CHANNEL_REQUEST, encodeString("exit-signal"), byte(0),
    encodeString("TERM"), byte(0), encodeString(""), encodeString(""));
  await packet(SSH_MSG_CHANNEL_EXTENDED_DATA, encodeUint32(1), encodeString("last line"));
  await packet(SSH_MSG_CHANNEL_EOF);
  const error = await outcome;
  assert.equal(error.signal, "TERM");
  assert.equal(error.exitCode, null);
  assert.equal(error.stderr, "last line");
});

test("EOF without status times out as unknown, and interrupted output with a known status is incomplete", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const first = await execFixture(25);
  await first.packet(SSH_MSG_CHANNEL_EOF);
  t.mock.timers.tick(25);
  const timeout = await first.outcome;
  assert.match(timeout.message, /超时.*结果未知/);
  assert.equal(timeout.exitCode, null);
  assert.equal(timeout.outputEnded, true);
  assert.equal(first.sent.filter((type) => type === SSH_MSG_CHANNEL_REQUEST).length, 1);

  const second = await execFixture();
  await second.packet(SSH_MSG_CHANNEL_REQUEST, ...status(7));
  await second.packet(SSH_MSG_DISCONNECT);
  const interrupted = await second.outcome;
  assert.match(interrupted.message, /输出可能不完整/);
  assert.equal(interrupted.exitCode, 7);
  assert.equal(interrupted.outputEnded, false);
});
