import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { jobStorage } from "./helpers/job-storage.mjs";
import test from "node:test";
import { JOB_OUTPUT_CAPACITY, MAX_JOB_PAGE_BYTES, McpJobOutput } from "../src/lib/mcp-job-output.ts";

function fixture(t) {
  const storage = jobStorage(t);
  return { storage, output: new McpJobOutput(storage) };
}

const raw = (frame) => Buffer.from(frame.base64, "base64");
const bytesOn = (page, stream) => Buffer.concat(page.frames.filter((f) => f.stream === stream).map(raw));
const textOn = (page, stream) => page.frames.filter((f) => f.stream === stream).map((f) => f.text).join("");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("more than 256 KiB is byte-exact after reconnect, with independent tail and legacy boundary lookups", (t) => {
  const { output, storage } = fixture(t);
  const lines = Array.from({ length: 12000 }, (_, i) => i.toString().padStart(5, "0") + " 香港测试 合成日志\n");
  const stdout = Buffer.from(["begin\n", ...lines, "end"].join(""));
  const stderr = Buffer.from("最后的错误。");
  assert.ok(stdout.length > 256 * 1024);
  for (let i = 0; i < stdout.length; i += 5003) output.append("stdout", stdout.subarray(i, i + 5003));
  output.append("stderr", stderr);
  const reader = new McpJobOutput(storage);
  const stdoutParts = [], stderrParts = [], visible = [];
  let cursor = 0;
  do {
    const page = reader.read(cursor, 3109);
    assert.deepEqual(reader.read(cursor, 3109), page);
    for (const frame of page.frames) {
      assert.equal(frame.offset, cursor);
      cursor += raw(frame).length;
    }
    assert.equal(cursor, page.nextCursor);
    assert.equal(page.hasMore, cursor < stdout.length + stderr.length);
    assert.deepEqual(page.missingRanges, []);
    stdoutParts.push(bytesOn(page, "stdout"));
    stderrParts.push(bytesOn(page, "stderr"));
    visible.push(textOn(page, "stdout"));
  } while (cursor < stdout.length + stderr.length);
  assert.equal(sha(Buffer.concat(stdoutParts)), sha(stdout));
  assert.deepEqual(Buffer.concat(stderrParts), stderr);
  assert.equal(visible.join(""), stdout.toString());
  assert.deepEqual(reader.summary(), {
    observedBytes: stdout.length + stderr.length, storedBytes: stdout.length + stderr.length,
    stdoutBytes: stdout.length, stderrBytes: stderr.length, missingRanges: [],
  });
  for (const i of [16383, 16384, 16385]) {
    assert.deepEqual(bytesOn(reader.read(i, 1), "stdout"), stdout.subarray(i, i + 1));
  }
  const tail = reader.tail(stderr.length);
  assert.equal(tail.startCursor, stdout.length);
  assert.equal(tail.hasMore, false);
  assert.deepEqual(bytesOn(tail, "stderr"), stderr);
  assert.equal(textOn(tail, "stderr"), stderr.toString());
});

test("UTF-8 previews follow each stream across blocks, interleaved packets, and one-byte pages", (t) => {
  const { output } = fixture(t);
  const border = 4095;
  output.append("stdout", Buffer.alloc(border, 65));
  const message = { stdout: Buffer.from("汉🍊文"), stderr: Buffer.from("🌏错") };
  const order = [];
  for (let i = 0; i < message.stdout.length; i++) {
    for (const ch of ["stdout", "stderr"]) {
      if (i >= message[ch].length) continue;
      output.append(ch, message[ch].subarray(i, i + 1));
      order.push(ch);
    }
  }
  const both = { stdout: "", stderr: "" };
  for (let i = 0; i < order.length; i++) {
    const page = output.read(border + i, 1);
    assert.equal(page.frames[0].stream, order[i]);
    both[order[i]] += page.frames[0].text;
  }
  assert.deepEqual(both, { stdout: "汉🍊文", stderr: "🌏错" });
  output.append("stdout", Uint8Array.of(255, 0, 0xf0));
  assert.deepEqual(bytesOn(output.tail(3), "stdout"), Buffer.from([255, 0, 0xf0]));
});

test("a quiet cursor gains data without changing the durable prefix or touching dispatch", (t) => {
  const { output, storage } = fixture(t);
  assert.deepEqual(output.tail().frames, []);
  output.append("stderr", Buffer.from("err"));
  const first = output.read(0, 3);
  assert.equal(first.nextCursor, 3);
  assert.deepEqual(output.read(first.nextCursor).frames, []);
  const reconnected = new McpJobOutput(storage);
  reconnected.append("stderr", Buffer.from("or"));
  assert.deepEqual(reconnected.read(0, 3).frames, first.frames);
  assert.equal(textOn(reconnected.read(3), "stderr"), "or");
  for (const cursor of [-1, 6, 1.5, NaN, "2"]) assert.throws(() => reconnected.read(cursor), RangeError);
  for (const size of [0, -1, MAX_JOB_PAGE_BYTES + 1, 0.5, NaN]) {
    assert.throws(() => reconnected.read(0, size), RangeError);
    assert.throws(() => reconnected.tail(size), RangeError);
  }
});

test("capacity overflow preserves the exact prefix and rolling tail and identifies every skipped offset", (t) => {
  const { output, storage } = fixture(t);
  const source = Buffer.alloc(JOB_OUTPUT_CAPACITY + 73_219);
  for (let i = 0; i < source.length; i++) source[i] = i % 251;
  output.append("stdout", source.subarray(0, JOB_OUTPUT_CAPACITY));
  assert.deepEqual(output.summary().missingRanges, []);
  output.append("stdout", source.subarray(JOB_OUTPUT_CAPACITY));
  const stderr = Buffer.from("tail error");
  output.append("stderr", stderr);
  const end = source.length + stderr.length;
  const gap = { start: JOB_OUTPUT_CAPACITY - MAX_JOB_PAGE_BYTES, end: end - MAX_JOB_PAGE_BYTES };
  assert.deepEqual(output.summary().missingRanges, [gap]);
  assert.equal(output.summary().storedBytes, JOB_OUTPUT_CAPACITY);
  const before = output.read(gap.start - 2, 16);
  assert.deepEqual(bytesOn(before, "stdout"), source.subarray(gap.start - 2, gap.start));
  assert.equal(before.nextCursor, gap.end);
  for (const cursor of [gap.start, gap.start + 17, gap.end]) {
    const after = output.read(cursor, 29);
    assert.equal(after.frames[0].offset, gap.end);
    assert.deepEqual(bytesOn(after, "stdout"), source.subarray(gap.end, gap.end + 29));
  }
  const tail = output.tail(MAX_JOB_PAGE_BYTES);
  assert.deepEqual(bytesOn(tail, "stdout"), source.subarray(gap.end));
  assert.deepEqual(bytesOn(tail, "stderr"), stderr);
  assert.equal(tail.nextCursor, end);
  storage.transactionSync(() => output.clear());
  assert.deepEqual(new McpJobOutput(storage).read().frames, []);
});

test("highly fragmented streams bound response overhead and tail still ends on the final byte", (t) => {
  const { output } = fixture(t);
  for (let i = 0; i < 301; i++) output.append(i % 2 ? "stderr" : "stdout", Uint8Array.of(i % 251));
  const first = output.read();
  assert.ok(first.nextCursor > 0 && first.nextCursor < 301);
  assert.equal(first.hasMore, true);
  const tail = output.tail();
  assert.ok(tail.startCursor > 0);
  assert.equal(tail.nextCursor, 301);
  assert.equal(tail.hasMore, false);
  assert.deepEqual(raw(tail.frames.at(-1)), Buffer.from([300 % 251]));
});

test("a direct stderr tail survives late stdout with exact stream offsets and a global resume cursor", (t) => {
  const { output, storage } = fixture(t);
  const stderr = Buffer.from("early stderr\n唯一报错🍊");
  const stdout = Buffer.alloc(4095, 65);
  output.append("stdout", stdout);
  // Split the multibyte text across SSH packets and physical output blocks.
  for (const byte of stderr) {
    output.append("stderr", Uint8Array.of(byte));
    output.append("stdout", Buffer.alloc(514, 66));
  }
  output.append("stdout", Buffer.alloc(256 * 1024, 67));
  const reader = new McpJobOutput(storage);
  assert.deepEqual(bytesOn(reader.tail(64), "stderr"), Buffer.alloc(0));
  for (const limit of [1, 4, 6, stderr.length, MAX_JOB_PAGE_BYTES]) {
    const page = reader.tail(limit, "stderr");
    const start = Math.max(0, stderr.length - limit);
    assert.equal("startCursor" in page, false);
    assert.equal("frames" in page, false);
    assert.equal(page.hasMore, false);
    assert.equal(page.nextCursor, reader.summary().observedBytes);
    const tail = page.streamTail;
    assert.equal(tail.stream, "stderr");
    assert.equal(tail.startOffset, start);
    assert.equal(tail.endOffset, stderr.length);
    assert.deepEqual(tail.missingRanges, []);
    assert.equal(tail.segments.length, 1);
    assert.equal(tail.segments[0].offset, start);
    assert.deepEqual(raw(tail.segments[0]), stderr.subarray(start));
    if (limit >= stderr.length) assert.equal(tail.segments[0].text, stderr.toString());
    if (limit === 1) assert.equal(tail.segments[0].text, "🍊");
  }
  const checkpoint = reader.tail(4, "stdout");
  assert.deepEqual(raw(checkpoint.streamTail.segments[0]), Buffer.from("CCCC"));
  assert.deepEqual(reader.read(checkpoint.nextCursor).frames, []);
  reader.append("stderr", Buffer.from("later"));
  assert.deepEqual(bytesOn(reader.read(checkpoint.nextCursor), "stderr"), Buffer.from("later"));
  assert.deepEqual(raw(reader.tail(5, "stderr").streamTail.segments[0]), Buffer.from("later"));
});

test("a filtered tail distinguishes empty streams, binary bytes, and invalid inputs", (t) => {
  const { output } = fixture(t);
  output.append("stderr", Uint8Array.of(255, 0, 0xf0));
  const stdout = output.tail(undefined, "stdout");
  assert.equal(stdout.nextCursor, 3);
  assert.deepEqual(stdout.streamTail, { stream: "stdout", startOffset: 0, endOffset: 0,
    missingRanges: [], segments: [] });
  assert.deepEqual(raw(output.tail(3, "stderr").streamTail.segments[0]), Buffer.from([255, 0, 0xf0]));
  for (const name of ["all", "", null]) assert.throws(() => output.tail(1, name), RangeError);
  for (const limit of [0, 1.5, MAX_JOB_PAGE_BYTES + 1]) {
    assert.throws(() => output.tail(limit, "stdout"), RangeError);
  }
  assert.deepEqual(output.tail(1, undefined), output.tail(1));
});

test("stream tails report precise losses between and inside retained blocks, including older jobs", (t) => {
  const { output, storage } = fixture(t);
  const head = JOB_OUTPUT_CAPACITY - MAX_JOB_PAGE_BYTES;
  output.append("stdout", Buffer.alloc(head - 1, 65));
  output.append("stderr", Buffer.from("AB"));
  // B is evicted physically; C sits in the stale part of a retained block.
  output.append("stdout", Buffer.alloc(4095, 66));
  output.append("stderr", Buffer.from("C"));
  output.append("stdout", Buffer.alloc(MAX_JOB_PAGE_BYTES, 67));
  output.append("stderr", Buffer.from("D"));
  function check(reader) {
    const page = reader.tail(10, "stderr");
    assert.deepEqual(page.missingRanges, [{ start: head, end: head + 4098 }]);
    assert.deepEqual(page.streamTail, {
      stream: "stderr", startOffset: 0, endOffset: 4, missingRanges: [{ start: 1, end: 3 }],
      segments: [
        { offset: 0, text: "A", base64: Buffer.from("A").toString("base64") },
        { offset: 3, text: "D", base64: Buffer.from("D").toString("base64") },
      ],
    });
    assert.deepEqual(reader.tail(2, "stderr").streamTail.missingRanges, [{ start: 2, end: 3 }]);
    assert.deepEqual(reader.tail(1, "stderr").streamTail.missingRanges, []);
    return page;
  }
  const before = check(output);
  // Simulate a pre-index DO with only its original durable tables.
  storage.sql.exec("DROP TABLE job_output_stream_blocks");
  const upgraded = new McpJobOutput(storage);
  assert.deepEqual(check(upgraded), before);
  upgraded.append("stderr", Buffer.from("E"));
  assert.deepEqual(raw(upgraded.tail(2, "stderr").streamTail.segments[0]), Buffer.from("DE"));
  upgraded.append("stdout", Buffer.alloc(MAX_JOB_PAGE_BYTES, 68));
  assert.deepEqual(upgraded.tail(4, "stderr").streamTail, {
    stream: "stderr", startOffset: 1, endOffset: 5,
    missingRanges: [{ start: 1, end: 5 }], segments: [],
  });
  storage.transactionSync(() => upgraded.clear());
  const fresh = new McpJobOutput(storage);
  assert.equal(fresh.tail(32, "stderr").nextCursor, 0);
  assert.deepEqual(fresh.tail(32, "stderr").streamTail.segments, []);
});

test("old complete jobs gain stream offsets before new bytes extend their last block", (t) => {
  const { output, storage } = fixture(t);
  output.append("stdout", Buffer.from("ok"));
  output.append("stderr", Buffer.from("err"));
  storage.sql.exec("DROP TABLE job_output_stream_blocks");
  const upgraded = new McpJobOutput(storage);
  upgraded.append("stderr", Buffer.from("or"));
  assert.deepEqual(raw(upgraded.tail(5, "stderr").streamTail.segments[0]), Buffer.from("error"));
  assert.deepEqual(raw(upgraded.tail(2, "stdout").streamTail.segments[0]), Buffer.from("ok"));
  // A previous Worker can append to the same physical block during rollback
  // without extending its stream index. Model that older index high-water mark.
  storage.sql.exec("UPDATE job_output_stream_blocks SET pastByte = 3 WHERE stream = 'stderr'");
  const restored = new McpJobOutput(storage);
  assert.deepEqual(raw(restored.tail(5, "stderr").streamTail.segments[0]), Buffer.from("error"));
});
