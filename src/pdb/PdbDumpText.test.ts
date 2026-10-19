import { expect, it } from "vitest";

import type { PdbSymbols } from "../domain/windowsArtifacts/pdbSymbols.js";
import {
  parsePdbDumpText,
  PdbDumpTextFailure,
  PDB_MAX_PRESERVED_LINES,
  PDB_MAX_UNPARSED_LINES,
} from "./PdbDumpText.js";

/**
 * Canned `llvm-pdbutil dump` text with the record shapes verified in LLVM's
 * own FileCheck tests (symbol-offset.test, modi.test, publics-yaml2pdb.test):
 * `<offset> | S_* [size = N] `name`` records with `addr = seg:off`
 * continuation lines, `Mod 0000` headings, and named-stream lines.
 */
const REPRESENTATIVE_DUMP = [
  "Summary:",
  "  ImageFile: C:\\src\\app.exe",
  "---STREAMS---",
  "Stream 0: [Block 5, Size 6588] PDB DBI Stream",
  "Stream 10: [Block 588, Size 42] Named Stream: '/names'",
  "Stream 17: [Block 640, Size 120] Named Stream: '/src/files/srcsrv.txt'",
  "---MODULES---",
  "Mod 0000 | `C:\\src\\main.obj`:",
  "Mod 0001 | `C:\\src\\lib.obj`:",
  "---SYMBOLS---",
  "Symbols",
  "Mod 0000",
  "   4 | S_GPROC32 [size = 44] `main`",
  "     parent = 0, end = 468, addr = 0001:0176, code size = 137",
  "  80 | S_LOCAL [size = 16] `argc`",
  "      type=0x0074 (int), flags = param",
  " 112 | S_CONSTANT [size = 22] `FOO`",
  "---PUBLICS---",
  "S_PUB32 [size = 44] `?AMethod@AClass@@QEAAXHPEAD@Z`",
  "     flags = function, addr = 0001:0480",
  "S_PUB32 [size = 28] `??_7Base@@6B@`",
  "     flags = none, addr = 0002:0000",
  "Total lines not modeled by this reader: example",
].join("\n");

const parse = (stdout: string): PdbSymbols => {
  const report = parsePdbDumpText(stdout);
  return {
    artifact: {
      path: "/artifacts/app.pdb",
      sha256: "0".repeat(64),
      bytes: 65536,
    },
    invocation: {
      command: "/usr/bin/llvm-pdbutil",
      arguments: [
        "dump",
        "-summary",
        "-streams",
        "-modules",
        "-files",
        "-symbols",
        "-publics",
        "/artifacts/app.pdb",
      ],
      exit: 0,
      stdout_bytes: stdout.length,
      stderr_bytes: 0,
    },
    srcsrv_executed: false,
    ...report,
  };
};

it("parses module headings with their names and repeats as raw lines", () => {
  const report = parse(REPRESENTATIVE_DUMP);
  // llvm-pdbutil repeats `Mod NNNN` headings per section; the bare symbols-
  // section heading groups into the first-seen compiland as a raw line.
  expect(report.modules).toEqual([
    {
      index: 0,
      name: "C:\\src\\main.obj",
      module_lines: ["Mod 0000 | `C:\\src\\main.obj`:", "Mod 0000"],
    },
    {
      index: 1,
      name: "C:\\src\\lib.obj",
      module_lines: ["Mod 0001 | `C:\\src\\lib.obj`:"],
    },
  ]);
});

it("parses CodeView symbol records with segment:offset addresses and code sizes", () => {
  const report = parse(REPRESENTATIVE_DUMP);
  expect(report.symbols).toEqual([
    {
      kind: "S_GPROC32",
      name: "main",
      record_offset: 4,
      size: 44,
      segment: 1,
      segment_offset: 0x176,
      code_size: 137,
      source_lines: expect.any(Array),
    },
    {
      kind: "S_LOCAL",
      name: "argc",
      record_offset: 80,
      size: 16,
      segment: null,
      segment_offset: null,
      code_size: null,
      source_lines: expect.any(Array),
    },
    {
      kind: "S_CONSTANT",
      name: "FOO",
      record_offset: 112,
      size: 22,
      segment: null,
      segment_offset: null,
      code_size: null,
      source_lines: expect.any(Array),
    },
    {
      kind: "S_PUB32",
      name: "?AMethod@AClass@@QEAAXHPEAD@Z",
      record_offset: null,
      size: 44,
      segment: 1,
      segment_offset: 0x480,
      code_size: null,
      source_lines: expect.any(Array),
    },
    {
      kind: "S_PUB32",
      name: "??_7Base@@6B@",
      record_offset: null,
      size: 28,
      segment: 2,
      segment_offset: 0,
      code_size: null,
      source_lines: expect.any(Array),
    },
  ]);
  expect(report.symbols[0]?.source_lines).toEqual([
    "   4 | S_GPROC32 [size = 44] `main`",
    "     parent = 0, end = 468, addr = 0001:0176, code size = 137",
  ]);
});

it("parses public symbol records with their flags and addresses", () => {
  const report = parse(REPRESENTATIVE_DUMP);
  const publics = report.symbols.filter(({ kind }) => kind === "S_PUB32");
  expect(publics).toHaveLength(2);
  expect(publics[0]).toMatchObject({
    name: "?AMethod@AClass@@QEAAXHPEAD@Z",
    segment: 1,
    segment_offset: 0x480,
    record_offset: null,
  });
  expect(publics[1]).toMatchObject({ segment: 2, segment_offset: 0 });
});

it("records named streams verbatim and flags /src/ streams as inert", () => {
  const report = parse(REPRESENTATIVE_DUMP);
  expect(report.named_streams).toEqual(["/names", "/src/files/srcsrv.txt"]);
  expect(report.srcsrv_streams_observed).toEqual(["/src/files/srcsrv.txt"]);
  expect(report.srcsrv_executed).toBe(false);
});

it("preserves unmatched lines verbatim and counts the total", () => {
  const report = parse(REPRESENTATIVE_DUMP);
  expect(report.unparsed_line_count).toBeGreaterThan(0);
  expect(report.unparsed_lines).toContain(
    "Total lines not modeled by this reader: example",
  );
  expect(report.raw_dump_lines[0]).toBe("Summary:");
  expect(report.complete).toBe(true);
});

it("caps preserved lines beyond the raw cap while still counting the rest", () => {
  const lines = Array.from(
    { length: PDB_MAX_PRESERVED_LINES + 10 },
    (_, index) => `line ${index}`,
  );
  const report = parse(lines.join("\n"));
  expect(report.unparsed_lines).toHaveLength(PDB_MAX_UNPARSED_LINES);
  expect(report.unparsed_line_count).toBe(PDB_MAX_PRESERVED_LINES + 10);
  expect(report.complete).toBe(false);
  expect(
    report.limitations.some((limitation) =>
      limitation.includes("preserved-line cap"),
    ),
  ).toBe(true);
});

it("keeps symbol-record association only for the immediately preceding record", () => {
  const report = parse(
    [
      "   4 | S_GPROC32 [size = 44] `main`",
      "     parent = 0, end = 468, addr = 0001:0176, code size = 137",
      "  80 | S_LOCAL [size = 16] `argc`",
      "      type=0x0074 (int), flags = param",
      "     addr = 0001:0500",
    ].join("\n"),
  );
  expect(report.symbols[0]).toMatchObject({
    segment: 1,
    segment_offset: 0x176,
    code_size: 137,
  });
  expect(report.symbols[1]).toMatchObject({
    segment: 1,
    segment_offset: 0x500,
    code_size: null,
  });
});
