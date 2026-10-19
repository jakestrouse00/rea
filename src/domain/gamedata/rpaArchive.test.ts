import { deflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";

import {
  buildRpa2,
  buildRpa3,
  buildRpa3Batched,
  pickleIndexOf,
  pickleIndexOfBatched,
  pickleInt,
  pickleString,
} from "./gamedataFixtures.js";
import {
  RpaFormatError,
  parseRpaArchive,
  parseRpaPickleIndex,
  rpaReportSchema,
} from "./rpaArchive.js";

const KEY = 0xdeadbeef;

describe("parseRpaPickleIndex", () => {
  it("evaluates the exact dict/list/tuple shape without memos", () => {
    const evaluated = parseRpaPickleIndex(
      pickleIndexOf({
        "images/bg.png": [[0x100000, 0x2000]],
        "script.rpyc": [
          [0x10, 0x20],
          [0x30, 0x40, Buffer.from("AB")],
        ],
      }),
    );
    expect(evaluated.protocol).toBe(2);
    expect([...evaluated.entries.keys()].sort()).toEqual([
      "images/bg.png",
      "script.rpyc",
    ]);
  });

  it("refuses opcodes outside the subset as a typed unknown", () => {
    // GLOBAL opcode 'c' is never part of a Ren'Py index.
    const bytes = Buffer.concat([
      Buffer.from([0x80, 2, 0x7d, 0x63]),
      Buffer.from("builtins.dictx\n", "ascii"),
    ]);
    expect(() => parseRpaPickleIndex(bytes)).toThrow(/0x63/u);
  });

  it("evaluates the CPython APPENDS batch form for a multi-item list", () => {
    const evaluated = parseRpaPickleIndex(
      pickleIndexOfBatched({
        "a/b.png": [
          [0x10, 0x20],
          [0x30, 0x40],
          [0x50, 0x60],
        ],
      }),
    );
    const list = evaluated.entries.get("a/b.png") as {
      items: readonly {
        items: readonly { type: string; value: number }[];
      }[];
    };
    expect(list.items).toHaveLength(3);
    expect(
      list.items.map((tuple) => tuple.items.map((item) => item.value)),
    ).toEqual([
      [0x10, 0x20],
      [0x30, 0x40],
      [0x50, 0x60],
    ]);
  });

  it("evaluates the CPython SETITEMS batch form for a multi-item dict", () => {
    const evaluated = parseRpaPickleIndex(
      Buffer.concat([
        Buffer.from([0x80, 2, 0x7d, 0x28]),
        pickleString("k1"),
        pickleInt(1),
        pickleString("k2"),
        pickleInt(2),
        pickleString("k3"),
        pickleInt(3),
        Buffer.from([0x75, 0x2e]),
      ]),
    );
    expect([...evaluated.entries.keys()]).toEqual(["k1", "k2", "k3"]);
  });
});

// oxlint-disable-next-line max-lines-per-function -- one golden archive suite shares the fixture builders; splitting describe blocks would rebuild the same bytes without new semantics.
describe("parseRpaArchive", () => {
  // oxlint-disable-next-line max-lines-per-function -- one golden assertion set over one built archive; splitting it would rebuild the same bytes without new semantics.
  it("deobfuscates stored offsets and lengths by XOR with the header key", () => {
    const plaintext = [
      {
        path: "images/sprite.png",
        offset: 0x8000,
        length: 0x4000,
      },
      {
        path: "audio/loop.ogg",
        offset: 0x100000,
        length: 0x800,
      },
    ];
    const index = Object.fromEntries(
      plaintext.map((entry) => [
        entry.path,
        [[(entry.offset ^ KEY) >>> 0, (entry.length ^ KEY) >>> 0] as const],
      ]),
    );
    const bytes = buildRpa3(KEY, index);
    const parsed = parseRpaArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.archive_format_version).toBe("3.0");
    expect(parsed.header_terminated_by_newline).toBe(true);
    expect(parsed.index.key_hex).toBe("deadbeef");
    expect(parsed.index.index_values_obfuscated).toBe(true);
    expect(parsed.index.readable).toBe(true);
    expect(parsed.index.slice).toEqual({
      entry_total: 2,
      entry_start: 0,
      entry_returned: 2,
      complete: true,
    });
    const [first] = parsed.index.entries;
    expect(first?.path).toBe("audio/loop.ogg");
    expect(first?.encrypted).toBe(true);
    expect(first?.segments[0]).toMatchObject({
      stored_offset: (0x100000 ^ KEY) >>> 0,
      stored_length: (0x800 ^ KEY) >>> 0,
      offset: 0x100000,
      length: 0x800,
      has_inline_prefix: false,
    });
  });

  it("records inline prefix segments by presence and length only", () => {
    const prefix = Buffer.from("prefixed-bytes", "latin1");
    const bytes = buildRpa3(KEY, {
      "video/intro.webm": [
        [(0x2000 ^ KEY) >>> 0, ((0x100 + prefix.length) ^ KEY) >>> 0, prefix],
      ],
    });
    const parsed = parseRpaArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    const entry = parsed.index.entries[0];
    expect(entry).toBeDefined();
    if (entry === undefined) return;
    expect(entry.segments[0]).toMatchObject({
      offset: 0x2000,
      has_inline_prefix: true,
      prefix_bytes: prefix.length,
    });
  });

  it("round-trips the batched APPENDS/SETITEMS CPython index shape", () => {
    const segments: [number, number][] = [
      [0x10, 0x20],
      [0x30, 0x40],
      [0x50, 0x60],
    ];
    const obfuscated = segments.map(
      ([offset, length]) =>
        [(offset ^ KEY) >>> 0, (length ^ KEY) >>> 0] as const,
    );
    const bytes = buildRpa3Batched(
      KEY,
      Object.fromEntries(
        ["a.rpyc", "b.rpyc", "c.rpyc"].map((path) => [path, obfuscated]),
      ),
    );
    const parsed = parseRpaArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.index.readable).toBe(true);
    expect(parsed.index.entry_total).toBe(3);
    expect(parsed.index.entries[0]?.segments).toHaveLength(3);
    expect(parsed.index.entries[0]?.segments[0]).toMatchObject({
      offset: 0x10,
      length: 0x20,
    });
    expect(parsed.index.entries[0]?.segments[2]).toMatchObject({
      offset: 0x50,
      length: 0x60,
    });
  });

  it("reports readable archives without obfuscation when the key is zero", () => {
    const bytes = buildRpa3(0, { "a.rpyb": [[0x300, 0x50]] });
    const parsed = parseRpaArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.index.index_values_obfuscated).toBe(false);
    const entry = parsed.index.entries[0];
    expect(entry?.encrypted).toBe(false);
    expect(entry?.segments[0]).toMatchObject({
      stored_offset: 0x300,
      offset: 0x300,
      stored_length: 0x50,
      length: 0x50,
    });
  });

  it("supports the unobfuscated RPA-2.0 header", () => {
    const bytes = buildRpa2({ "b.rpyc": [[0x400, 0x60]] });
    const parsed = parseRpaArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.archive_format_version).toBe("2.0");
    expect(parsed.header_bytes).toBe(25);
    expect(parsed.index.key_hex).toBe("00000000");
    expect(parsed.index.entry_total).toBe(1);
  });

  it("keeps the refused-pickle unknown typed instead of evaluating", () => {
    const unsupported = Buffer.concat([
      Buffer.from([0x80, 2, 0x7d, 0x63]),
      Buffer.from("builtins.dictx\n", "ascii"),
    ]);
    const bytes = Buffer.concat([
      Buffer.from(
        "RPA-3.0 " +
          (40).toString(16).padStart(16, "0") +
          " " +
          KEY.toString(16).padStart(8, "0") +
          "\n",
        "ascii",
      ),
      Buffer.alloc(40 - 34, 0x41),
      deflateSync(unsupported),
    ]);
    const parsed = parseRpaArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.index.readable).toBe(false);
    expect(parsed.index.unsupported_detail).toMatch(/0x63/u);
    expect(parsed.index.entries).toEqual([]);
    expect(parsed.index.entry_total).toBe(0);
  });

  it("rejects malformed headers and round-trips the report schema", () => {
    expect(() =>
      parseRpaArchive(Buffer.alloc(64, 0x51), {
        entries_start: 0,
        entries_limit: 10,
      }),
    ).toThrow(RpaFormatError);
    const badOffset = Buffer.from(
      "RPA-3.0 xxxxxxxxxxxxxxxx deadbeef\n",
      "ascii",
    );
    expect(() =>
      parseRpaArchive(badOffset, { entries_start: 0, entries_limit: 10 }),
    ).toThrow(RpaFormatError);
    const bytes = buildRpa3(KEY, {
      "c.rpyc": [[(0x10 ^ KEY) >>> 0, (0x20 ^ KEY) >>> 0]],
    });
    const report = rpaReportSchema.parse({
      ...parseRpaArchive(bytes, { entries_start: 0, entries_limit: 10 }),
      artifact: {
        path: "/tmp/game/archive.rpa",
        sha256: "0".repeat(64),
        bytes: bytes.length,
      },
    });
    expect(report.limitations.length).toBeGreaterThan(0);
  });
});
