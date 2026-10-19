import { expect, it } from "vitest";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type {
  InspectRustSymbolsInput,
  RustSymbolsReport,
} from "../../domain/rust/rustBinary.js";
import { ok } from "../../domain/result.js";
import { RustSymbolsService } from "./RustSymbolsService.js";

const identity = {
  id: "fixture-rust-symbols",
  name: "Source-owned Rust symbol reader seam",
  version: "1",
};

const report: RustSymbolsReport = {
  artifact: { path: "/artifacts/program", sha256: "a".repeat(64), bytes: 4096 },
  format: "elf",
  architecture: "amd64",
  bits: 64,
  byte_order: "little",
  table: "symtab",
  offset: 0,
  limit: 50,
  entries: [
    {
      index: 1,
      mangled: "_ZN4main17h45e8b8c6e3b6b5f0E",
      format: "legacy",
      demangled: "main",
      demangle_failure_reason: null,
      value_hex: "0x401000",
      size: 10,
      binding: "global",
      section_index: 2,
      file_offset: 4000,
    },
    {
      index: 3,
      mangled: "memcpy",
      format: "other",
      demangled: null,
      demangle_failure_reason: "Name does not use a Rust mangling scheme",
      value_hex: "0x0",
      size: null,
      binding: "global",
      section_index: null,
      file_offset: null,
    },
  ],
  summary: {
    declared_symbols: 4,
    named_symbols: 3,
    complete: true,
    mangled_legacy: 2,
    mangled_v0: 0,
    mangled_other: 1,
    demangled_ok: 1,
    demangled_failed: 1,
  },
  limitations: [
    "Symbol names, values, sizes and bindings are table content. They do not authenticate package ownership or prove which compiler produced the binary.",
  ],
};

it("rejects relative paths and strict-schema violations before reading", async () => {
  let calls = 0;
  const service = new RustSymbolsService({
    identity,
    symbols: (input: InspectRustSymbolsInput) => {
      calls += 1;
      void input;
      return Promise.resolve(ok(report));
    },
  });
  const relative = await service.symbols({ path: "program" });
  const extra = await service.symbols({
    path: report.artifact.path,
    detail: "complete",
  });
  const page = await service.symbols({
    path: report.artifact.path,
    limit: 501,
  });
  expect(relative.ok).toBe(false);
  expect(extra.ok).toBe(false);
  expect(page.ok).toBe(false);
  if (!relative.ok) expect(relative.error).toBeInstanceOf(AnalysisInputError);
  if (!extra.ok) expect(extra.error).toBeInstanceOf(AnalysisInputError);
  if (!page.ok) expect(page.error).toBeInstanceOf(AnalysisInputError);
  expect(calls).toBe(0);
});

it("returns an already-cancelled request without reading", async () => {
  let calls = 0;
  const service = new RustSymbolsService({
    identity,
    symbols: () => {
      calls += 1;
      return Promise.resolve(ok(report));
    },
  });
  const controller = new AbortController();
  controller.abort();
  const result = await service.symbols(
    { path: report.artifact.path },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
  expect(calls).toBe(0);
});

it("binds the page to the selected artifact as observed Evidence", async () => {
  let received: InspectRustSymbolsInput | undefined;
  const result = await new RustSymbolsService({
    identity,
    symbols: (input) => {
      received = input;
      return Promise.resolve(ok(report));
    },
  }).symbols({ path: report.artifact.path });
  expect(received).toEqual({
    path: report.artifact.path,
    offset: 0,
    limit: 50,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "observed",
    operation: "inspect_rust_symbols",
    subject: { format: "elf", architecture: "x86_64" },
    normalized_result: report,
    locations: [{ kind: "artifact-path", path: report.artifact.path }],
  });
});

it("rejects provider output that does not match the report schema", async () => {
  const mismatched = {
    ...report,
    summary: { ...report.summary, demangled_ok: 7 },
  };
  const result = await new RustSymbolsService({
    identity,
    symbols: () => Promise.resolve(ok(mismatched as RustSymbolsReport)),
  }).symbols({ path: report.artifact.path });
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisOutputError", operation: "inspect_rust_symbols" },
  });
});
