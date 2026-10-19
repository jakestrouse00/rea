import { expect, it } from "vitest";

import {
  type WindowsMinidump,
  windowsMinidumpSchema,
} from "../domain/windowsArtifacts/windowsMinidump.js";
import {
  MINIDUMP_MAX_ENTRIES,
  MINIDUMP_MAX_STREAMS,
  MinidumpFormatFailure,
  MinidumpResourceFailure,
  parseWindowsMinidump,
} from "./WindowsMinidump.js";
import {
  buildMinidumpFixture,
  representativeMinidump,
} from "./WindowsMinidump.fixture.js";

const parseRepresentative = (): WindowsMinidump => {
  const fixture = representativeMinidump();
  return parseWindowsMinidump(
    { bytes: fixture.bytes, sha256: fixture.sha256 },
    { path: "/artifacts/example.dmp" },
  );
};

it("parses the header, directory and every modeled stream of a representative dump", () => {
  const report = parseRepresentative();
  expect(report.artifact).toMatchObject({
    path: "/artifacts/example.dmp",
    bytes: report.artifact.bytes,
  });
  expect(report.format_version).toBe(42899);
  expect(report.timestamp).toBe(1729200000);
  expect(report.flags).toBe("0");
  expect(report.streams.map((stream) => stream.type)).toEqual([
    3, 4, 5, 6, 7, 19,
  ]);
  expect(report.streams.map((stream) => stream.status)).toEqual([
    "parsed",
    "parsed",
    "parsed",
    "parsed",
    "parsed",
    "unparsed",
  ]);
  expect(report.examined).toMatchObject({
    streams: 6,
    parsed_streams: 5,
    unparsed_streams: 1,
    modules: 1,
    threads: 2,
    memory_ranges: 2,
    memory_info_entries: 0,
  });
});

it("preserves the unparsed stream as a located directory entry without content", () => {
  const report = parseRepresentative();
  const unparsed = report.streams.find((stream) => stream.type === 19);
  expect(unparsed).toBeDefined();
  expect(unparsed?.status).toBe("unparsed");
  expect(windowsMinidumpSchema.safeParse(report).success).toBe(true);
});

it("reports module names, image ranges and fixed version-info fields verbatim", () => {
  const report = parseRepresentative();
  expect(report.modules).toHaveLength(1);
  const module = report.modules[0];
  expect(module?.name).toEqual({
    name: "C:\\Windows\\System32\\example.dll",
    name_rva: expect.any(Number),
    raw_bytes_base64: Buffer.from(
      "C:\\Windows\\System32\\example.dll",
      "utf16le",
    ).toString("base64"),
  });
  expect(module?.base).toBe(0x7ff600000000n.toString(10));
  expect(module?.size).toBe(0x1000);
  expect(module?.checksum).toBe(0x1234);
  expect(module?.timestamp).toBe(1729000000);
  expect(module?.version_info_signature).toBe(0xf00fee04);
  expect(module?.file_version_ms).toBe(10);
  expect(module?.product_version_ls).toBe(3);
});

it("records thread addresses only and keeps CONTEXT contents unknown", () => {
  const report = parseRepresentative();
  const [first, second] = report.threads;
  expect(first).toMatchObject({
    id: 4040,
    suspend_count: 0,
    priority_class: 2,
    teb: 0x7ffdf0000000n.toString(10),
    stack: { start_of_memory_range: 0x0f1000n.toString(10) },
  });
  expect(first?.stack.memory.data_size).toBe(16);
  expect(first?.context.data_size).toBe(0x4d0);
  expect(second?.suspend_count).toBe(1);
  expect(second?.stack.memory.data_size).toBe(8);
});

it("returns the exception code, address and parameter vector", () => {
  const report = parseRepresentative();
  expect(report.exception).toMatchObject({
    thread_id: 4040,
    code: 0xc0000005,
    flags: 0,
    address: 0x7ff600000123n.toString(10),
    parameter_count: 2,
    parameters: ["0", 0x7ff600000123n.toString(10)],
  });
  expect(report.exception?.thread_context).not.toBeNull();
});

it("parses the numeric system-info identity and preserves the CSD location", () => {
  const report = parseRepresentative();
  expect(report.system_info).toEqual({
    processor_architecture: 9,
    processor_level: 6,
    processor_revision: 0x0302,
    number_of_processors: 8,
    product_type: 1,
    major_version: 10,
    minor_version: 0,
    build_number: 19045,
    platform_id: 2,
    csd_version_rva: 0,
    suite_mask: 0x0100,
  });
  expect(
    report.limitations.some((limitation) =>
      limitation.includes("CSD (service-pack) string"),
    ),
  ).toBe(true);
});

it("inventories MemoryList ranges at their declared file locations", () => {
  const report = parseRepresentative();
  expect(report.memory_ranges).toHaveLength(2);
  const range = report.memory_ranges[0];
  expect(range?.start).toBe(0x0f1000n.toString(10));
  expect(range?.data_size).toBe(16);
  expect(range?.rva).toBeGreaterThan(0);
  expect(range?.rva ?? 0).toBeLessThan(report.artifact.bytes);
});

it("inventories a Memory64 list with sequential data offsets and region facts", () => {
  const fixture = buildMinidumpFixture({
    streams: [
      {
        kind: "memory64-list",
        ranges: [
          { start: 0x10000n, bytes: 32 },
          { start: 0x20000n, bytes: 64 },
        ],
      },
      {
        kind: "memory-info-list",
        entries: [
          {
            base: 0x10000n,
            allocationBase: 0x10000n,
            allocationProtect: 0x40,
            regionSize: 0x1000n,
            state: 0x1000,
            protect: 0x04,
            type: 0x20000,
          },
        ],
      },
    ],
  });
  const report = parseWindowsMinidump(
    { bytes: fixture.bytes, sha256: fixture.sha256 },
    { path: "/artifacts/memory64.dmp" },
  );
  expect(report.memory64_ranges).toEqual([
    {
      start: 0x10000n.toString(10),
      data_size: "32",
      data_offset: expect.stringMatching(/^[0-9]+$/),
    },
    {
      start: 0x20000n.toString(10),
      data_size: "64",
      data_offset: expect.stringMatching(/^[0-9]+$/),
    },
  ]);
  const firstOffset = Number(report.memory64_ranges[0]?.data_offset ?? "0");
  const secondOffset = Number(report.memory64_ranges[1]?.data_offset ?? "0");
  expect(secondOffset).toBe(firstOffset + 32);
  expect(firstOffset).toBeGreaterThan(0);
  expect(report.memory_info.list).toEqual({
    size_of_header: 16,
    size_of_entry: 48,
    number_of_entries: "1",
  });
  expect(report.memory_info.entries).toEqual([
    {
      base: 0x10000n.toString(10),
      allocation_base: 0x10000n.toString(10),
      allocation_protect: 0x40,
      region_size: 0x1000n.toString(10),
      state: 0x1000,
      protect: 0x04,
      type: 0x20000,
    },
  ]);
});

it("reports an exception stream without a thread context location as null context", () => {
  const fixture = buildMinidumpFixture({
    streams: [
      {
        kind: "exception",
        exception: {
          threadId: 7,
          code: 0xc0000409,
          address: 1n,
          omitContext: true,
        },
      },
    ],
  });
  const report = parseWindowsMinidump(
    { bytes: fixture.bytes, sha256: fixture.sha256 },
    { path: "/artifacts/no-context.dmp" },
  );
  expect(report.exception?.code).toBe(0xc0000409);
  expect(report.exception?.thread_context).toEqual({ data_size: 0, rva: 0 });
});

it("rejects a Memory64 range whose declared extent leaves the snapshot as malformed", () => {
  const fixture = buildMinidumpFixture({
    streams: [
      { kind: "memory64-list", ranges: [{ start: 0x10000n, bytes: 32 }] },
    ],
  });
  const declared = Buffer.concat([
    Buffer.from("0000010000000000", "hex"),
    Buffer.from("2000000000000000", "hex"),
  ]);
  const patternAt = fixture.bytes.indexOf(declared);
  expect(patternAt).toBeGreaterThan(0);
  fixture.bytes.writeBigUInt64LE(0xffff4000n, patternAt + 8);
  const fail = () =>
    parseWindowsMinidump(
      { bytes: fixture.bytes, sha256: fixture.sha256 },
      { path: "/artifacts/memory64-overflow.dmp" },
    );
  expect(fail).toThrow(MinidumpFormatFailure);
  expect(fail).toThrow(
    /Memory64ListStream range 0 at data offset \d+ declares \d+ bytes beyond the snapshot/,
  );
});

it("discloses truncated and duplicate modeled streams instead of inventing facts", () => {
  const fixture = buildMinidumpFixture({
    streams: [
      { kind: "unparsed", type: 6, bytes: [1, 2, 3] },
      {
        kind: "exception",
        exception: { threadId: 7, code: 0xc0000409, address: 1n },
      },
    ],
  });
  const report = parseWindowsMinidump(
    { bytes: fixture.bytes, sha256: fixture.sha256 },
    { path: "/artifacts/duplicate-exception.dmp" },
  );
  expect(report.exception).toBeNull();
  expect(
    report.limitations.some((limitation) =>
      limitation.includes("ExceptionStream declares 3 bytes"),
    ),
  ).toBe(true);
  expect(
    report.limitations.some((limitation) =>
      limitation.includes("2 ExceptionStream directory entries"),
    ),
  ).toBe(true);
});

it("rejects a report whose memory64 range leaves the artifact during re-validation", () => {
  const fixture = buildMinidumpFixture({
    streams: [
      { kind: "memory64-list", ranges: [{ start: 0x10000n, bytes: 32 }] },
    ],
  });
  const report = parseWindowsMinidump(
    { bytes: fixture.bytes, sha256: fixture.sha256 },
    { path: "/artifacts/memory64.dmp" },
  );
  const tampered = {
    ...report,
    memory64_ranges: [{ start: "0", data_size: "999999", data_offset: "0" }],
  };
  expect(windowsMinidumpSchema.safeParse(tampered).success).toBe(false);
});

it("rejects a non-MDMP artifact as unsupported and a truncated header as malformed", () => {
  const garbage = Buffer.alloc(64, 7);
  expect(() =>
    parseWindowsMinidump(
      { bytes: garbage, sha256: "0".repeat(64) },
      { path: "/artifacts/not-a-dump.bin" },
    ),
  ).toThrow(MinidumpFormatFailure);
  expect(() =>
    parseWindowsMinidump(
      { bytes: Buffer.from("MDMP"), sha256: "0".repeat(64) },
      { path: "/artifacts/short.dmp" },
    ),
  ).toThrow(MinidumpFormatFailure);
});

it("fails typed when a declared stream count or table exceeds its budget", () => {
  const fixture = buildMinidumpFixture({ streams: [] });
  fixture.bytes.writeUInt32LE(MINIDUMP_MAX_STREAMS + 1, 8);
  expect(() =>
    parseWindowsMinidump(
      { bytes: fixture.bytes, sha256: fixture.sha256 },
      { path: "/artifacts/streams.dmp" },
    ),
  ).toThrow(MinidumpResourceFailure);
  const many = Array.from({ length: 2 }, () => ({
    kind: "unparsed" as const,
    type: 19,
  }));
  const directoryFlood = buildMinidumpFixture({ streams: many });
  directoryFlood.bytes.writeUInt32LE(2, 8);
  expect(() =>
    parseWindowsMinidump(
      {
        bytes: Buffer.concat([directoryFlood.bytes.subarray(0, 40)]),
        sha256: "0".repeat(64),
      },
      { path: "/artifacts/short-directory.dmp" },
    ),
  ).toThrow(MinidumpFormatFailure);
  expect(MINIDUMP_MAX_ENTRIES).toBe(65536);
});

it("fails typed when a thread table declares entries beyond its stream bytes", () => {
  const fixture = representativeMinidump();
  const threadStreamType = 3;
  const header = 32;
  const directoryEntry = 0;
  const threadListRva = fixture.bytes.readUInt32LE(
    header + (directoryEntry + 0) * 12 + 8,
  );
  const threadListRvaIsFirst =
    fixture.bytes.readUInt32LE(header + (directoryEntry + 0) * 12) ===
    threadStreamType;
  expect(threadListRvaIsFirst).toBe(true);
  fixture.bytes.writeUInt32LE(60000, threadListRva);
  expect(() =>
    parseWindowsMinidump(
      { bytes: fixture.bytes, sha256: fixture.sha256 },
      { path: "/artifacts/thread-flood.dmp" },
    ),
  ).toThrow(MinidumpFormatFailure);
});
