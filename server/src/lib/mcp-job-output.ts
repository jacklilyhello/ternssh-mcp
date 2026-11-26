export type JobStream = "stdout" | "stderr";

export const JOB_OUTPUT_CAPACITY = 4 * 1024 * 1024;
export const MAX_JOB_PAGE_BYTES = 32 * 1024;
const DEFAULT_PAGE_BYTES = 8192;
const BLOCK_BYTES = 4096;
const HEAD_BYTES = JOB_OUTPUT_CAPACITY - MAX_JOB_PAGE_BYTES;
// Bound JSON overhead even when the streams alternate on every byte.
const PAGE_FRAMES = 128;

type Counters = {
  stdout: number;
  stderr: number;
  outSeed: ArrayBuffer | null;
  errSeed: ArrayBuffer | null;
};
type Block = {
  start: number;
  data: ArrayBuffer;
  channels: ArrayBuffer;
  outSeed: ArrayBuffer | null;
  errSeed: ArrayBuffer | null;
};
type OutputFrame = {
  stream: JobStream;
  offset: number;
  base64: string;
  text: string;
};
export type OutputSummary = {
  observedBytes: number;
  storedBytes: number;
  stdoutBytes: number;
  stderrBytes: number;
  missingRanges: { start: number; end: number }[];
};
export type OutputPage = OutputSummary & {
  startCursor: number;
  nextCursor: number;
  hasMore: boolean;
  frames: OutputFrame[];
};
type ByteRange = { start: number; end: number };
type StreamTailPage = OutputSummary & {
  nextCursor: number;
  hasMore: false;
  streamTail: {
    stream: JobStream;
    startOffset: number;
    endOffset: number;
    missingRanges: ByteRange[];
    segments: { offset: number; base64: string; text: string }[];
  };
};

const blockStart = (n: number) => n - n % BLOCK_BYTES;
const bit = (channels: Uint8Array, index: number) => (channels[index >> 3] >> (index & 7)) & 1;

// Three preceding stream bytes are sufficient to seed a UTF-8 decoder at
// any byte position, including inside a four-byte scalar.
function seedBefore(previous: ArrayBuffer | null, bytes: Uint8Array, end: number): ArrayBuffer {
  if (end >= 3) return Uint8Array.from(bytes.subarray(end - 3, end)).buffer;
  const prior = previous ? new Uint8Array(previous).slice(end - 3) : new Uint8Array();
  const seed = new Uint8Array(prior.length + end);
  seed.set(prior);
  seed.set(bytes.subarray(0, end), prior.length);
  return seed.buffer;
}

function decoderAt(seed: ArrayBuffer | null) {
  const decoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
  if (seed?.byteLength) decoder.decode(seed, { stream: true });
  return decoder;
}

function checkLimit(limit: number) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_JOB_PAGE_BYTES) {
    throw new RangeError("Invalid output page size");
  }
}

/** Job cursors count raw bytes in combined arrival order. Offsets nested
 * inside streamTail count only the selected stream. A UTF-8 scalar appears
 * when it completes; base64 is authoritative for binary data. */
export class McpJobOutput {
  private readonly sql: SqlStorage;

  constructor(private readonly storage: DurableObjectStorage) {
    this.sql = storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS job_output_counts (
      id INTEGER PRIMARY KEY, stdout INTEGER, stderr INTEGER, outSeed BLOB, errSeed BLOB)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS job_output_blocks (
      start INTEGER PRIMARY KEY, data BLOB, channels BLOB, outSeed BLOB, errSeed BLOB)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS job_output_stream_blocks (
      stream TEXT NOT NULL, blockStart INTEGER NOT NULL, firstByte INTEGER NOT NULL,
      pastByte INTEGER NOT NULL, PRIMARY KEY(stream,blockStart))`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS job_output_stream_end
      ON job_output_stream_blocks(stream,pastByte)`);
    // The previous Worker can also have extended an indexed block during a
    // rollback. Compare its physical length with both indexed channel lengths.
    const legacy = this.sql.exec(`SELECT 1 FROM
      (SELECT start, length(data) AS size FROM job_output_blocks ORDER BY start DESC LIMIT 1) AS last
      WHERE last.size != COALESCE((SELECT SUM(pastByte - firstByte)
        FROM job_output_stream_blocks WHERE stream IN ('stdout', 'stderr') AND blockStart = last.start), 0)`).toArray();
    if (legacy.length) this.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM job_output_stream_blocks");
      this.indexLegacyBlocks();
    });
  }

  // Existing jobs have stream totals and per-block channel bitmaps. Index
  // the retained prefix forwards and the retained suffix backwards from the
  // totals to recover exact stream offsets even across an evicted interval.
  private indexLegacyBlocks() {
    const summary = this.summary();
    const head = { stdout: 0, stderr: 0 };
    const tail = { stdout: summary.stdoutBytes, stderr: summary.stderrBytes };
    const blocks = this.sql.exec<{ start: number; size: number; channels: ArrayBuffer }>(
      "SELECT start, length(data) AS size, channels FROM job_output_blocks ORDER BY start",
    ).toArray();
    const rows: [JobStream, number, number, number][] = [];
    // Only bitmaps are loaded (at most one bit per retained raw byte).
    const index = (block: typeof blocks[number], backwards: boolean) => {
      let stderr = 0;
      for (let bits of new Uint8Array(block.channels)) {
        while (bits) {
          bits &= bits - 1;
          stderr++;
        }
      }
      const counts = { stderr, stdout: block.size - stderr };
      for (const stream of ["stdout", "stderr"] as const) {
        const count = counts[stream];
        if (!count) continue;
        const first = backwards ? tail[stream] - count : head[stream];
        if (backwards) tail[stream] = first;
        else head[stream] += count;
        rows.push([stream, block.start, first, first + count]);
      }
    };
    const gap = summary.missingRanges[0];
    for (const block of blocks) {
      if (gap && block.start >= gap.start) break;
      index(block, false);
    }
    if (gap) {
      for (const block of blocks.reverse()) {
        if (block.start < gap.start) break;
        index(block, true);
      }
    }
    this.sql.exec(`INSERT INTO job_output_stream_blocks (stream,blockStart,firstByte,pastByte)
      SELECT json_extract(value,'$[0]'), json_extract(value,'$[1]'),
             json_extract(value,'$[2]'), json_extract(value,'$[3]') FROM json_each(?)`, JSON.stringify(rows));
  }

  private counters(): Counters {
    return this.sql.exec<Counters>(
      "SELECT stdout, stderr, outSeed, errSeed FROM job_output_counts WHERE id = 1",
    ).toArray()[0] ?? { stdout: 0, stderr: 0, outSeed: new ArrayBuffer(0), errSeed: new ArrayBuffer(0) };
  }

  summary(): OutputSummary {
    const { stdout, stderr } = this.counters();
    const observedBytes = stdout + stderr;
    return {
      observedBytes, storedBytes: Math.min(observedBytes, JOB_OUTPUT_CAPACITY),
      stdoutBytes: stdout, stderrBytes: stderr,
      missingRanges: observedBytes > JOB_OUTPUT_CAPACITY
        ? [{ start: HEAD_BYTES, end: observedBytes - MAX_JOB_PAGE_BYTES }] : [],
    };
  }

  append(stream: JobStream, bytes: Uint8Array): void {
    if (!bytes.length) return;
    this.storage.transactionSync(() => {
      const state = this.counters();
      const start = state.stdout + state.stderr;
      const end = start + bytes.length;
      const isErr = stream === "stderr";
      const seed = isErr ? state.errSeed : state.outSeed;
      const tailBlock = blockStart(end - MAX_JOB_PAGE_BYTES);
      let offset = start;
      while (offset < end) {
        // Eviction keeps a prefix and a rolling tail. An oversized packet can
        // jump directly across the gap without ever writing discarded blocks.
        if (end > JOB_OUTPUT_CAPACITY && offset >= HEAD_BYTES && offset < tailBlock) {
          offset = tailBlock;
        }
        const startOfBlock = blockStart(offset);
        const at = offset - startOfBlock;
        const stop = Math.min(end - startOfBlock, BLOCK_BYTES);
        const old = at ? this.getBlock(startOfBlock) : undefined;
        const data = new Uint8Array(stop);
        const channels = new Uint8Array(Math.ceil(stop / 8));
        if (old) {
          data.set(new Uint8Array(old.data));
          channels.set(new Uint8Array(old.channels));
        }
        data.set(bytes.subarray(offset - start, startOfBlock + stop - start), at);
        if (isErr) {
          for (let i = at; i < stop; i++) channels[i >> 3] |= 1 << (i & 7);
        }
        this.sql.exec(
          "INSERT OR REPLACE INTO job_output_blocks (start,data,channels,outSeed,errSeed) VALUES (?,?,?,?,?)",
          startOfBlock, data.buffer, channels.buffer,
          old ? old.outSeed : (isErr ? state.outSeed : seedBefore(seed, bytes, offset - start)),
          old ? old.errSeed : (isErr ? seedBefore(seed, bytes, offset - start) : state.errSeed),
        );
        this.sql.exec(`INSERT INTO job_output_stream_blocks (stream,blockStart,firstByte,pastByte)
          VALUES (?,?,?,?) ON CONFLICT(stream,blockStart) DO UPDATE SET pastByte=excluded.pastByte`,
          stream, startOfBlock, state[stream] + offset - start, state[stream] + startOfBlock + stop - start);
        offset = startOfBlock + stop;
      }
      if (end > JOB_OUTPUT_CAPACITY) {
        this.sql.exec("DELETE FROM job_output_blocks WHERE start >= ? AND start < ?", HEAD_BYTES, tailBlock);
        for (const channel of ["stdout", "stderr"]) {
          this.sql.exec("DELETE FROM job_output_stream_blocks WHERE stream = ? AND blockStart >= ? AND blockStart < ?",
            channel, HEAD_BYTES, tailBlock);
        }
      }
      state[stream] += bytes.length;
      state[isErr ? "errSeed" : "outSeed"] = seedBefore(seed, bytes, bytes.length);
      this.sql.exec("INSERT OR REPLACE INTO job_output_counts VALUES (1,?,?,?,?)",
        state.stdout, state.stderr, state.outSeed, state.errSeed);
    });
  }

  private getBlock(start: number): Block {
    return this.sql.exec<Block>("SELECT * FROM job_output_blocks WHERE start = ?", start).one();
  }

  private blocks(start: number, end: number) {
    if (start === end) return [];
    const first = blockStart(start);
    const last = blockStart(end - 1);
    const blocks = this.sql.exec<Block>(
      "SELECT * FROM job_output_blocks WHERE start BETWEEN ? AND ? ORDER BY start", first, last,
    ).toArray();
    if (blocks.length !== 1 + (last - first) / BLOCK_BYTES) throw new Error("Output blocks unavailable");
    return blocks;
  }

  read(cursor = 0, limitBytes = DEFAULT_PAGE_BYTES): OutputPage {
    checkLimit(limitBytes);
    const summary = this.summary();
    if (!Number.isSafeInteger(cursor) || cursor < 0 || cursor > summary.observedBytes) {
      throw new RangeError("Invalid output cursor");
    }
    const gap = summary.missingRanges[0];
    const start = gap && cursor >= gap.start && cursor < gap.end ? gap.end : cursor;
    const end = Math.min(start + limitBytes, gap && start < gap.start ? gap.start : summary.observedBytes);
    const frames: OutputFrame[] = [];
    let next = start;
    for (const block of this.blocks(start, end)) {
      const data = new Uint8Array(block.data);
      const channels = new Uint8Array(block.channels);
      const decoders = [decoderAt(block.outSeed), decoderAt(block.errSeed)];
      const from = Math.max(0, start - block.start);
      const to = Math.min(data.length, end - block.start);
      let i = 0;
      while (i < to && frames.length < PAGE_FRAMES) {
        const channel = bit(channels, i);
        const boundary = i < from ? from : to;
        let stop = i + 1;
        while (stop < boundary && bit(channels, stop) === channel) stop++;
        const bytes = data.subarray(i, stop);
        const text = decoders[channel].decode(bytes, { stream: true });
        if (i >= from) {
          frames.push({ stream: channel ? "stderr" : "stdout", offset: block.start + i,
            base64: btoa(String.fromCharCode(...bytes)), text });
          next = block.start + stop;
        }
        i = stop;
      }
      if (frames.length === PAGE_FRAMES) break;
    }
    if (gap && next === gap.start) next = gap.end;
    return { ...summary, frames, startCursor: cursor, nextCursor: next, hasMore: next < summary.observedBytes };
  }

  private streamTail(stream: JobStream, limit: number, summary: OutputSummary): StreamTailPage {
    const endOffset = stream === "stderr" ? summary.stderrBytes : summary.stdoutBytes;
    const startOffset = Math.max(0, endOffset - limit);
    const data = new Uint8Array(endOffset - startOffset);
    const parts: (ByteRange & { text: string })[] = [];
    const missingRanges: ByteRange[] = [];
    let cursor = startOffset;
    // Seek by stream offset so a quiet stderr does not require reading all
    // the stdout blocks that arrived after it.
    const blocks = this.sql.exec<Block & { firstByte: number }>(`SELECT b.*, s.firstByte
      FROM job_output_stream_blocks s JOIN job_output_blocks b ON b.start = s.blockStart
      WHERE s.stream = ? AND s.pastByte > ? AND s.firstByte < ? ORDER BY s.pastByte`,
      stream, startOffset, endOffset).toArray();
    const channel = stream === "stderr" ? 1 : 0;
    const gap = summary.missingRanges[0];
    for (const block of blocks) {
      const raw = new Uint8Array(block.data);
      const channels = new Uint8Array(block.channels);
      const filtered = new Uint8Array(raw.length);
      let count = 0;
      let skipped = 0;
      for (let i = 0; i < raw.length; i++) {
        if (bit(channels, i) !== channel) continue;
        filtered[count++] = raw[i];
        // The first retained suffix block may physically contain bytes from
        // the gap. Those bytes seed the decoder but are never returned.
        if (gap && block.start >= gap.start && block.start + i < gap.end) skipped++;
      }
      const from = Math.max(skipped, startOffset - block.firstByte);
      const to = Math.min(count, endOffset - block.firstByte);
      if (from >= to) continue;
      const start = block.firstByte + from;
      const end = block.firstByte + to;
      const bytes = filtered.subarray(from, to);
      const decoder = decoderAt(channel ? block.errSeed : block.outSeed);
      decoder.decode(filtered.subarray(0, from), { stream: true });
      const text = decoder.decode(bytes, { stream: true });
      data.set(bytes, start - startOffset);
      if (start > cursor) missingRanges.push({ start: cursor, end: start });
      const last = parts[parts.length - 1];
      if (last && start === last.end) {
        last.end = end;
        last.text += text;
      } else {
        parts.push({ start, end, text });
      }
      cursor = end;
    }
    if (cursor < endOffset) missingRanges.push({ start: cursor, end: endOffset });
    const segments = parts.map(({ start, end, text }) => ({
      offset: start, text, base64: btoa(String.fromCharCode(...data.subarray(start - startOffset, end - startOffset))),
    }));
    return { ...summary, nextCursor: summary.observedBytes, hasMore: false,
      streamTail: { stream, startOffset, endOffset, missingRanges, segments } };
  }

  tail(limitBytes?: number): OutputPage;
  tail(limitBytes: number | undefined, stream: JobStream): StreamTailPage;
  tail(limitBytes?: number, stream?: JobStream): OutputPage | StreamTailPage;
  tail(limitBytes = DEFAULT_PAGE_BYTES, stream?: JobStream): OutputPage | StreamTailPage {
    checkLimit(limitBytes);
    const summary = this.summary();
    if (stream !== undefined) {
      if (stream !== "stderr" && stream !== "stdout") throw new RangeError("Invalid output stream");
      return this.streamTail(stream, limitBytes, summary);
    }
    const { observedBytes } = summary;
    const start = Math.max(0, observedBytes - limitBytes);
    // Match the frame budget from the end so a fragmented tail still
    // includes the last byte. read() splits frames at block boundaries.
    let count = 0;
    for (const block of this.blocks(start, observedBytes).reverse()) {
      const channels = new Uint8Array(block.channels);
      let nextChannel = -1;
      for (let i = block.data.byteLength - 1; i >= Math.max(0, start - block.start); i--) {
        const channel = bit(channels, i);
        if (channel !== nextChannel && ++count > PAGE_FRAMES) return this.read(block.start + i + 1, limitBytes);
        nextChannel = channel;
      }
    }
    return this.read(start, limitBytes);
  }

  /** The caller may group erasure and its expiry tombstone in a single
   * storage.transactionSync() to preserve replay protection after expiry. */
  clear(): void {
    this.sql.exec("DELETE FROM job_output_stream_blocks");
    this.sql.exec("DELETE FROM job_output_blocks");
    this.sql.exec("DELETE FROM job_output_counts");
  }
}
