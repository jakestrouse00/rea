import { createHash } from "node:crypto";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  LIEF_BRIDGE_DIR_ENV,
  LIEF_BRIDGE_FILE_NAME,
  LIEF_COMMAND_ENV,
  LIEF_IMPORT_REMEDIATION,
} from "../domain/lief/liefLimits.js";
import {
  LiefBridgeRunError,
  type LiefBridgeRunOutput,
} from "./LiefBridgeClient.js";
import { LiefDeepProvider, type LiefBridgeRunner } from "./LiefDeepProvider.js";

const BRIDGE = {
  lief_version: "0.16.0",
  python_version: "3.13.1",
  capabilities: { dwarf: true, pdb: true, fat: true },
} as const;

const ELF_REPORT = {
  format: "elf",
  architectures: [
    {
      index: 0,
      cpu: "x86_64",
      bits: 64,
      little_endian: true,
      entrypoint: 0x401000,
      image_base: 0x400000,
      size: null,
      offset: null,
    },
  ],
  structure_summary: { section_count: 4, segment_count: 3 },
  dynamic: {
    soname: "libexample.so.1",
    rpath: [],
    runpath: ["/opt/run"],
    needed_count: 1,
    entries: [{ tag: "flags_1", value: 1 }],
  },
  macho: null,
  pe: null,
  debug_sources: {
    dwarf: {
      present: true,
      sections: [{ name: ".debug_info", size: 256 }],
    },
    pdb_reference: null,
  },
  truncated: {
    dynamic_entries: false,
    data_directories: false,
    debug_entries: false,
    debug_sections: false,
  },
  complete: true,
  limitations: ["LIEF reports the parsed object; offsets are not re-verified."],
} as const;

const DEBUG_REPORT = {
  artifact_kind: "elf",
  debug_sources: {
    dwarf: {
      present: true,
      sections: [{ name: ".debug_info", size: 256 }],
      compilation_unit_count: 1,
      function_count: 2,
    },
    pdb: {
      reference: null,
      available: true,
      public_symbol_count: null,
      compilation_unit_count: null,
    },
  },
  queries: [
    {
      query: { kind: "symbol", name: "main" },
      outcome: "found",
      matches: [
        {
          kind: "dwarf_function",
          name: "main",
          address: 0x401000,
          size: 0x40,
          rva: null,
          compilation_unit: "main.c",
        },
      ],
      reason: null,
    },
    {
      query: { kind: "symbol", name: "absent" },
      outcome: "not_found",
      matches: [],
      reason: null,
    },
  ],
  truncated: {
    queries: false,
    matches: false,
    dwarf_functions: false,
    public_symbols: false,
  },
  complete: true,
  limitations: [],
} as const;

interface Harness {
  readonly provider: LiefDeepProvider;
  readonly path: string;
  readonly sha256: string;
  readonly requests: readonly string[];
}

const frame = (operation: string, report: unknown): string =>
  JSON.stringify({
    kind: "lief_report",
    protocol: 1,
    operation,
    bridge: BRIDGE,
    report,
  });

const refusal = (code: string, message: string): string =>
  JSON.stringify({ kind: "lief_error", protocol: 1, code, message });

const ARTIFACT_BYTES = Buffer.from("\u007fELF\u0000artificial", "binary");

const harness = async (
  reply: (request: unknown) => string | Promise<string> | never,
): Promise<Harness> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-lief-provider-"));
  const command = join(directory, "python3");
  await writeFile(command, "#!/bin/sh\nexit 0\n");
  await chmod(command, 0o755);
  await writeFile(join(directory, LIEF_BRIDGE_FILE_NAME), "# bridge\n");
  const path = join(directory, "example.elf");
  await writeFile(path, ARTIFACT_BYTES);
  const requests: string[] = [];
  const runner: LiefBridgeRunner = async (input) => {
    requests.push(input.request);
    const output = await reply(JSON.parse(input.request));
    const result: LiefBridgeRunOutput = {
      line: output,
      exitCode: 0,
      stderr: "",
      stderrTruncated: false,
    };
    return result;
  };
  return {
    provider: new LiefDeepProvider(
      {
        [LIEF_COMMAND_ENV]: command,
        [LIEF_BRIDGE_DIR_ENV]: directory,
      },
      runner,
    ),
    path,
    sha256: createHash("sha256").update(ARTIFACT_BYTES).digest("hex"),
    requests,
  };
};

describe("LiefDeepProvider structure reports", () => {
  it("binds the request to the artifact digest and returns the reported structure", async () => {
    const selected = await harness(() =>
      frame("inspect_binary_deep", ELF_REPORT),
    );
    const report = await selected.provider.inspectBinaryDeep({
      path: selected.path,
    });
    expect(report.ok).toBe(true);
    if (!report.ok) throw new Error(report.error.message);
    expect(report.value.artifact).toEqual({
      path: selected.path,
      sha256: selected.sha256,
      bytes: ARTIFACT_BYTES.length,
    });
    expect(report.value.format).toBe("elf");
    expect(report.value.dynamic?.needed_count).toBe(1);
    expect(report.value.limitations).toContain(
      "LIEF-derived facts are the caller-selected release's interpretation; REA does not re-derive them.",
    );
    const request = JSON.parse(selected.requests[0] ?? "{}");
    expect(request).toMatchObject({
      protocol: 1,
      operation: "inspect_binary_deep",
      path: selected.path,
      artifact: { sha256: selected.sha256, bytes: ARTIFACT_BYTES.length },
    });
    expect(report.value.delegated_facts.map(({ tool }) => tool)).toContain(
      "inspect_binary_layout",
    );
  });

  it("refuses an unsupported container with the bridge's own reason", async () => {
    const selected = await harness(() =>
      refusal(
        "unsupported_format",
        "the artifact's magic bytes are not ELF, PE or Mach-O",
      ),
    );
    const report = await selected.provider.inspectBinaryDeep({
      path: selected.path,
    });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisUnsupportedTargetError");
  });

  it("refuses a LIEF release outside the declared range", async () => {
    const selected = await harness(() =>
      JSON.stringify({
        kind: "lief_report",
        protocol: 1,
        operation: "inspect_binary_deep",
        bridge: { ...BRIDGE, lief_version: "0.9.0" },
        report: ELF_REPORT,
      }),
    );
    const report = await selected.provider.inspectBinaryDeep({
      path: selected.path,
    });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(report.error).toMatchObject({
      remediationAction: LIEF_IMPORT_REMEDIATION,
    });
  });

  it("refuses a report frame for another operation", async () => {
    const selected = await harness(() =>
      frame("extract_pdb_dwarf_info", DEBUG_REPORT),
    );
    const report = await selected.provider.inspectBinaryDeep({
      path: selected.path,
    });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisOutputError");
  });

  it("refuses an artifact that changed between hashing and parsing", async () => {
    const selected = await harness(() =>
      frame("inspect_binary_deep", {
        ...ELF_REPORT,
        artifact: {
          path: "/artifacts/other.elf",
          sha256: "f".repeat(64),
          bytes: ARTIFACT_BYTES.length,
        },
      }),
    );
    const report = await selected.provider.inspectBinaryDeep({
      path: selected.path,
    });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisArtifactChangedError");
  });
});

describe("LiefDeepProvider failure projection", () => {
  it("refuses malformed frames, protocol drift and oversized lines", async () => {
    const invalid = await harness(() => "not json");
    const invalidReport = await invalid.provider.inspectBinaryDeep({
      path: invalid.path,
    });
    expect(invalidReport.ok).toBe(false);

    const drifted = await harness(() =>
      JSON.stringify({
        kind: "lief_report",
        protocol: 2,
        operation: "inspect_binary_deep",
        bridge: BRIDGE,
        report: ELF_REPORT,
      }),
    );
    const drift = await drifted.provider.inspectBinaryDeep({
      path: drifted.path,
    });
    expect(drift.ok).toBe(false);
    if (drift.ok) throw new Error("expected refusal");
    expect(drift.error.message).toContain("protocol 2");

    const oversized = await harness(() => {
      throw new LiefBridgeRunError("output-limit", "oversized frame", {
        stderr: "",
        exit_code: null,
      });
    });
    const limited = await oversized.provider.inspectBinaryDeep({
      path: oversized.path,
    });
    expect(limited.ok).toBe(false);
    if (limited.ok) throw new Error("expected refusal");
    expect(limited.error._tag).toBe("AnalysisResourceConstraintError");
  });

  it("carries cancellation and deadline refusals through", async () => {
    const cancelled = await harness(() => {
      throw new LiefBridgeRunError("cancelled", "cancelled");
    });
    const cancelledReport = await cancelled.provider.inspectBinaryDeep({
      path: cancelled.path,
    });
    expect(cancelledReport.ok).toBe(false);
    if (cancelledReport.ok) throw new Error("expected refusal");
    expect(cancelledReport.error._tag).toBe("AnalysisCancelledError");

    const timedOut = await harness(() => {
      throw new LiefBridgeRunError("timeout", "deadline elapsed");
    });
    const timeoutReport = await timedOut.provider.inspectBinaryDeep({
      path: timedOut.path,
    });
    expect(timeoutReport.ok).toBe(false);
    if (timeoutReport.ok) throw new Error("expected refusal");
    expect(timeoutReport.error._tag).toBe("AnalysisTimeoutError");
  });

  it("refuses before any run when the lane is not configured", async () => {
    const provider = new LiefDeepProvider({}, async () => {
      throw new Error("the bridge must not run");
    });
    const report = await provider.inspectBinaryDeep({
      path: "/artifacts/example",
    });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(report.error).toMatchObject({
      providerId: "lief",
      operation: "inspect_binary_deep",
    });
  });

  it("refuses a pre-aborted signal without hashing or running", async () => {
    const selected = await harness(() =>
      frame("inspect_binary_deep", ELF_REPORT),
    );
    const controller = new AbortController();
    controller.abort(new Error("stop"));
    const report = await selected.provider.inspectBinaryDeep(
      { path: selected.path },
      { signal: controller.signal },
    );
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisCancelledError");
    expect(selected.requests).toHaveLength(0);
  });
});

describe("LiefDeepProvider debug-info lookups", () => {
  it("passes the caller's exact lookups and returns found/not_found outcomes", async () => {
    const selected = await harness(() =>
      frame("extract_pdb_dwarf_info", DEBUG_REPORT),
    );
    const report = await selected.provider.extractPdbDwarfInfo({
      path: selected.path,
      queries: [
        { kind: "symbol", name: "main" },
        { kind: "symbol", name: "absent" },
      ],
    });
    expect(report.ok).toBe(true);
    if (!report.ok) throw new Error(report.error.message);
    expect(report.value.queries.map(({ outcome }) => outcome)).toEqual([
      "found",
      "not_found",
    ]);
    expect(JSON.parse(selected.requests[0] ?? "{}").queries).toEqual([
      { kind: "symbol", name: "main" },
      { kind: "symbol", name: "absent" },
    ]);
  });

  it("refuses a report that contradicts its own outcome", async () => {
    const selected = await harness(() =>
      frame("extract_pdb_dwarf_info", {
        ...DEBUG_REPORT,
        queries: [
          {
            query: { kind: "symbol", name: "main" },
            outcome: "not_found",
            matches: [
              {
                kind: "dwarf_function",
                name: "main",
                address: 1,
                size: 1,
                rva: null,
                compilation_unit: null,
              },
            ],
            reason: null,
          },
        ],
      }),
    );
    const report = await selected.provider.extractPdbDwarfInfo({
      path: selected.path,
      queries: [{ kind: "symbol", name: "main" }],
    });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisOutputError");
  });

  it("refuses a frame that claims completeness while a truncation row is set", async () => {
    const selected = await harness(() =>
      frame("extract_pdb_dwarf_info", {
        ...DEBUG_REPORT,
        truncated: {
          queries: true,
          matches: false,
          dwarf_functions: false,
          public_symbols: false,
        },
      }),
    );
    const report = await selected.provider.extractPdbDwarfInfo({
      path: selected.path,
    });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisOutputError");
  });

  it("refuses more lookups than the fixed budget", async () => {
    const selected = await harness(() =>
      frame("extract_pdb_dwarf_info", DEBUG_REPORT),
    );
    const report = await selected.provider.extractPdbDwarfInfo({
      path: selected.path,
      queries: Array.from({ length: 65 }, (_, index) => ({
        kind: "symbol" as const,
        name: `symbol_${String(index)}`,
      })),
    });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected refusal");
    expect(report.error._tag).toBe("AnalysisInputError");
    expect(selected.requests).toHaveLength(0);
  });
});
