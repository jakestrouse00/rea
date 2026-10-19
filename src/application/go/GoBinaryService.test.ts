import { expect, it } from "vitest";
import { GoBinaryService } from "./GoBinaryService.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type {
  GoBinary,
  GoPclntab,
  GoProcedureTable,
} from "../../domain/go/goBinary.js";
import { parseEvidence } from "../../domain/evidence.js";
import { ok } from "../../domain/result.js";

const identity = {
  id: "fixture-go",
  name: "Source-owned Go reader seam",
  version: "1",
};
const stubProcedureTable = () => Promise.resolve(ok(procedureReport));
const report: GoBinary = {
  artifact: { path: "/artifacts/program", sha256: "a".repeat(64), bytes: 1024 },
  format: "elf",
  architecture: "riscv64",
  bits: 64,
  byte_order: "little",
  build_info: null,
  limitations: ["Build information unavailable."],
};

it("rejects invalid paths and extra caller arguments before invoking the reader", async () => {
  let calls = 0;
  const service = new GoBinaryService({
    identity,
    inspect: () => {
      calls += 1;
      return Promise.resolve(ok(report));
    },
    procedureTable: stubProcedureTable,
  });
  for (const input of [
    { path: "relative" },
    { path: "/artifacts/\0program" },
    { path: report.artifact.path, execute: true },
  ]) {
    const result = await service.inspect(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisInputError);
  }
  expect(calls).toBe(0);
});

it("preserves unsupported subject architectures and does not duplicate metadata", async () => {
  const service = new GoBinaryService({
    identity,
    inspect: () => Promise.resolve(ok(report)),
    procedureTable: stubProcedureTable,
  });
  const result = await service.inspect({ path: report.artifact.path });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value.subject).toMatchObject({
    architecture: null,
    local_path: report.artifact.path,
    digest: { sha256: report.artifact.sha256 },
  });
  expect(result.value.normalized_result).toEqual(report);
  expect(result.value.raw_result).toBeNull();
});

it("preserves byte-valued build metadata and validates compiler source lengths", async () => {
  const moduleBytes = Buffer.concat([
    Buffer.from("3077af0c9274080241e1c107e6d618e6", "hex"),
    Buffer.from([0xff, 10]),
    Buffer.from("f932433186182072008242104116d8f2", "hex"),
  ]);
  const buildInfo: NonNullable<GoBinary["build_info"]> = {
    header_offset: 64,
    encoding: "inline",
    go_version: null,
    go_version_bytes_base64: "/w==",
    module_text: null,
    module_bytes_base64: moduleBytes.toString("base64"),
    version_location: { offset: 128, bytes: 1 },
    module_location: { offset: 256, bytes: moduleBytes.length },
    module: {
      path: null,
      main: null,
      dependencies: [],
      settings: [],
      unparsed_lines: [],
      unparsed_line_bytes_base64: ["/w=="],
      complete: false,
    },
  };
  const partial: GoBinary = {
    ...report,
    build_info: buildInfo,
    limitations: ["Some embedded strings contain non-UTF-8 bytes."],
  };
  const result = await new GoBinaryService({
    identity,
    inspect: () => Promise.resolve(ok(partial)),
    procedureTable: stubProcedureTable,
  }).inspect({ path: report.artifact.path });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toEqual(partial);

  const mismatched: GoBinary = {
    ...partial,
    build_info: {
      ...buildInfo,
      version_location: { offset: 128, bytes: 2 },
    },
  };
  const invalid = await new GoBinaryService({
    identity,
    inspect: () => Promise.resolve(ok(mismatched)),
    procedureTable: stubProcedureTable,
  }).inspect({ path: report.artifact.path });
  expect(invalid.ok).toBe(false);
  if (!invalid.ok) expect(invalid.error).toBeInstanceOf(AnalysisOutputError);
});

it("refuses reader identity changes and invalid original source ranges", async () => {
  const outside: GoBinary = {
    ...report,
    build_info: {
      header_offset: 1000,
      encoding: "inline",
      go_version: "go1.26.0",
      go_version_bytes_base64: Buffer.from("go1.26.0").toString("base64"),
      module_text: "",
      module_bytes_base64: "",
      version_location: { offset: 2000, bytes: 8 },
      module_location: { offset: 0, bytes: 0 },
      module: {
        path: null,
        main: null,
        dependencies: [],
        settings: [],
        unparsed_lines: [],
        unparsed_line_bytes_base64: [],
        complete: true,
      },
    },
  };
  for (const value of [
    { ...report, artifact: { ...report.artifact, path: "/artifacts/other" } },
    outside,
  ]) {
    const result = await new GoBinaryService({
      identity,
      inspect: () => Promise.resolve(ok(value)),
      procedureTable: stubProcedureTable,
    }).inspect({ path: report.artifact.path });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
  }
});

it("honors cancellation before reading and after a completed observation", async () => {
  const controller = new AbortController();
  const reason = { request: "late Go cancellation" };
  let calls = 0;
  const service = new GoBinaryService({
    identity,
    inspect: () => {
      calls += 1;
      controller.abort(reason);
      return Promise.resolve(ok(report));
    },
    procedureTable: stubProcedureTable,
  });
  const completed = await service.inspect(
    { path: report.artifact.path },
    { signal: controller.signal },
  );
  expect(completed.ok).toBe(false);
  if (!completed.ok) {
    expect(completed.error).toBeInstanceOf(AnalysisCancelledError);
    expect(completed.error.cause).toBe(reason);
    expect(parseEvidence(completed.error.partialObservation)).toMatchObject({
      operation: "inspect_go_binary",
      normalized_result: report,
    });
  }
  const before = await service.inspect(
    { path: report.artifact.path },
    { signal: controller.signal },
  );
  expect(before.ok).toBe(false);
  if (!before.ok) expect(before.error).toBeInstanceOf(AnalysisCancelledError);
  expect(calls).toBe(1);
});

it("keeps malformed provider output ahead of a late cancellation", async () => {
  const controller = new AbortController();
  const malformed = {
    ...report,
    artifact: { ...report.artifact, path: "/other" },
  };
  const result = await new GoBinaryService({
    identity,
    inspect: () => {
      controller.abort();
      return Promise.resolve(ok(malformed));
    },
    procedureTable: stubProcedureTable,
  }).inspect({ path: report.artifact.path }, { signal: controller.signal });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
});

it.each([
  null,
  "caller cancellation",
  { request: "opaque caller value" },
  new Error("caller failure"),
  new AnalysisOutputError("caller_operation", "caller-owned cleanup", {
    cleanup: {
      reason: "unresolved caller resource",
      resources: ["caller resource"],
    },
  }),
])(
  "preserves an opaque admission cancellation reason without invoking the reader: %j",
  async (reason) => {
    const controller = new AbortController();
    controller.abort(reason);
    let calls = 0;
    const service = new GoBinaryService({
      identity,
      inspect: async () => {
        calls += 1;
        throw new Error("cancelled admission must not invoke the reader");
      },
      procedureTable: stubProcedureTable,
    });
    const result = await service.inspect(null, { signal: controller.signal });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected cancelled admission");
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(result.error.cause).toBe(reason);
    expect(result.error.cleanupIncomplete).toBe(false);
    expect(result.error.partialObservation).toBeUndefined();
    expect(calls).toBe(0);
    if (reason instanceof AnalysisOutputError)
      expect(reason.cleanupIncomplete).toBe(true);
  },
);

const procedureIdentity = {
  id: "fixture-go-procedures",
  name: "Source-owned Go procedure-table seam",
  version: "1",
};
const procedureReport: GoProcedureTable = {
  artifact: {
    path: "/artifacts/program",
    sha256: "a".repeat(64),
    bytes: 4096,
  },
  format: "elf",
  architecture: "amd64",
  bits: 64,
  byte_order: "little",
  pclntab: {
    location: {
      source: "section",
      section_name: ".gopclntab",
      file_offset: 2048,
      address: "0x401800",
      bytes: 1024,
    },
    magic: "0xfffffff1",
    era: "go1.20+",
    min_lc: 1,
    ptr_size: 8,
    nfunc: 2,
    nfiles: 1,
    funcname_bytes: 33,
    functab: { file_offset: 2112, entry_width: 8, count: 3 },
    text_start: "0x401000",
    text_base: { address: "0x401000", source: "pclntab-header" },
    moduledata: {
      found: true,
      file_offset: 4096,
      nfunc_matches: true,
      text_address: "0x401000",
    },
    legacy: false,
  },
  offset: 0,
  limit: 50,
  total: 2,
  procedures: [
    {
      index: 0,
      name: "main.main",
      entry_offset: 0,
      end_offset: 3,
      entry_address: "0x401000",
      end_address: "0x401003",
    },
    {
      index: 1,
      name: null,
      entry_offset: 3,
      end_offset: 9,
      entry_address: "0x401003",
      end_address: "0x401009",
    },
  ],
  next_offset: null,
  limitations: ["Source-file mappings are not decoded."],
};

it("rejects invalid procedure-table paging and paths before invoking the provider", async () => {
  let calls = 0;
  const service = new GoBinaryService({
    identity: procedureIdentity,
    inspect: () => Promise.resolve(ok(report)),
    procedureTable: () => {
      calls += 1;
      return Promise.resolve(ok(procedureReport));
    },
  });
  for (const input of [
    { path: "relative" },
    { path: "/artifacts/program", limit: 0 },
    { path: "/artifacts/program", limit: 501 },
    { path: "/artifacts/program", offset: -1 },
    { path: "/artifacts/program", unrelated: true },
  ]) {
    const result = await service.procedureTable(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisInputError);
  }
  expect(calls).toBe(0);
});

it("wraps a procedure-table page in artifact-bound Evidence with a pclntab range", async () => {
  const result = await new GoBinaryService({
    identity: procedureIdentity,
    inspect: () => Promise.resolve(ok(report)),
    procedureTable: () => Promise.resolve(ok(procedureReport)),
  }).procedureTable({
    path: procedureReport.artifact.path,
    offset: 0,
    limit: 50,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value.subject).toMatchObject({
    format: "elf",
    architecture: "x86_64",
    local_path: procedureReport.artifact.path,
    digest: { sha256: procedureReport.artifact.sha256 },
  });
  expect(result.value.normalized_result).toEqual(procedureReport);
  expect(result.value.raw_result).toBeNull();
  expect(result.value.operation).toBe("inspect_go_procedure_table");
  expect(result.value.locations).toEqual([
    { kind: "artifact-path", path: procedureReport.artifact.path },
    { kind: "file-offset-range", start: 2048, end: 3072 },
  ]);
});

it("refuses procedure-table reports that change the artifact or violate paging", async () => {
  const changed = {
    ...procedureReport,
    artifact: { ...procedureReport.artifact, path: "/artifacts/other" },
  };
  const drifted = {
    ...procedureReport,
    next_offset: 5,
  };
  if (procedureReport.pclntab === null)
    throw new Error("fixture invariant: pclntab present");
  const miscountedPclntab: GoPclntab = {
    ...procedureReport.pclntab,
    nfunc: 3,
  };
  const miscounted = {
    ...procedureReport,
    pclntab: miscountedPclntab,
  };
  const service = new GoBinaryService({
    identity: procedureIdentity,
    inspect: () => Promise.resolve(ok(report)),
    procedureTable: () => Promise.resolve(ok(drifted)),
  });
  for (const value of [changed, miscounted]) {
    const result = await new GoBinaryService({
      identity: procedureIdentity,
      inspect: () => Promise.resolve(ok(report)),
      procedureTable: () => Promise.resolve(ok(value)),
    }).procedureTable({ path: procedureReport.artifact.path });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
  }
  const driftedResult = await service.procedureTable({
    path: procedureReport.artifact.path,
  });
  expect(driftedResult.ok).toBe(false);
  if (!driftedResult.ok)
    expect(driftedResult.error).toBeInstanceOf(AnalysisOutputError);
});

it("keeps a tableless report valid without pclntab locations", async () => {
  const absent: GoProcedureTable = {
    ...procedureReport,
    pclntab: null,
    total: 0,
    procedures: [],
  };
  const result = await new GoBinaryService({
    identity: procedureIdentity,
    inspect: () => Promise.resolve(ok(report)),
    procedureTable: () => Promise.resolve(ok(absent)),
  }).procedureTable({ path: procedureReport.artifact.path });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value.locations).toEqual([
    { kind: "artifact-path", path: procedureReport.artifact.path },
  ]);
});

it("honors cancellation around the procedure-table read", async () => {
  const controller = new AbortController();
  const reason = { request: "late procedure-table cancellation" };
  let calls = 0;
  const service = new GoBinaryService({
    identity: procedureIdentity,
    inspect: () => Promise.resolve(ok(report)),
    procedureTable: () => {
      calls += 1;
      controller.abort(reason);
      return Promise.resolve(ok(procedureReport));
    },
  });
  const completed = await service.procedureTable(
    { path: procedureReport.artifact.path },
    { signal: controller.signal },
  );
  expect(completed.ok).toBe(false);
  if (!completed.ok) {
    expect(completed.error).toBeInstanceOf(AnalysisCancelledError);
    expect(completed.error.cause).toBe(reason);
    expect(parseEvidence(completed.error.partialObservation)).toMatchObject({
      operation: "inspect_go_procedure_table",
      normalized_result: procedureReport,
    });
  }
  const before = await service.procedureTable(
    { path: procedureReport.artifact.path, offset: 2, limit: 1 },
    { signal: controller.signal },
  );
  expect(before.ok).toBe(false);
  if (!before.ok) expect(before.error).toBeInstanceOf(AnalysisCancelledError);
  expect(calls).toBe(1);
});
