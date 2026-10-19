import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it as test } from "vitest";

import { createWindowsArtifactsService } from "../../../../src/composition/windowsArtifacts.js";
import type { PdbSymbols } from "../../../../src/domain/windowsArtifacts/pdbSymbols.js";
import type { WerReport } from "../../../../src/domain/windowsArtifacts/werReport.js";
import type { WindowsMinidump } from "../../../../src/domain/windowsArtifacts/windowsMinidump.js";
import {
  representativeMinidump,
  buildMinidumpFixture,
} from "../../../../src/windows/WindowsMinidump.fixture.js";
import { inspectLlvmPdbutil } from "../../../../src/pdb/PdbDoctor.js";
import { inspectWindowsArtifacts } from "../../../../src/windows/WindowsArtifactsDoctor.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const it = test.skipIf(process.platform === "win32");

const REPRESENTATIVE_DUMP_OUTPUT = [
  "Summary:",
  "  ImageFile: C:\\src\\app.exe",
  "---STREAMS---",
  "Stream 0: [Block 5, Size 6588] PDB DBI Stream",
  "Stream 17: [Block 640, Size 120] Named Stream: '/src/files/srcsrv.txt'",
  "---MODULES---",
  "Mod 0000 | `C:\\src\\main.obj`:",
  "---SYMBOLS---",
  "Symbols",
  "Mod 0000",
  "   4 | S_GPROC32 [size = 44] `main`",
  "     parent = 0, end = 468, addr = 0001:0176, code size = 137",
  "---PUBLICS---",
  "S_PUB32 [size = 44] `?AMethod@AClass@@QEAAXHPEAD@Z`",
  "     flags = function, addr = 0001:0480",
].join("\n");

/** A caller-configured llvm-pdbutil stand-in running the given shell body. */
const writeFakeLlvmPdbutilScript = async (
  directory: string,
  body: string,
): Promise<string> => {
  const path = join(directory, "llvm-pdbutil-fake.sh");
  await writeFile(path, `#!/bin/sh\n${body}\n`);
  await chmod(path, 0o755);
  return path;
};

/** A stand-in that prints a fixed dump output; the quoted heredoc keeps every
 * byte (backticks, `$`, quotes) verbatim regardless of shell expansion. */
const writeFakeLlvmPdbutilDump = async (
  directory: string,
  output: string,
): Promise<string> =>
  writeFakeLlvmPdbutilScript(
    directory,
    `cat <<'REA_FAKE_PDBUTIL_EOF'\n${output}\nREA_FAKE_PDBUTIL_EOF`,
  );

it("inspects a materialized minidump through the composed service and Evidence", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const dumpPath = join(root, "example.dmp");
  const fixture = representativeMinidump();
  await writeFile(dumpPath, fixture.bytes);
  const service = createWindowsArtifactsService(process.env);
  try {
    const result = await service.inspectMinidump({ path: dumpPath });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error.message);
    const report = result.value.normalized_result as WindowsMinidump;
    expect(report.artifact).toEqual({
      path: dumpPath,
      sha256: fixture.sha256,
      bytes: fixture.bytes.length,
    });
    expect(report.streams.map(({ type }) => type)).toEqual([3, 4, 5, 6, 7, 19]);
    expect(report.exception?.code).toBe(0xc0000005);
    expect(result.value.evidence_id.startsWith("ev_")).toBe(true);
    expect(result.value.subject?.digest).toEqual({ sha256: fixture.sha256 });
  } finally {
    await service.close();
  }
});

it("inspects a materialized WER report and preserves its values verbatim", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const reportPath = join(root, "AppCrash.wer");
  const text = [
    "EventType=APPCRASH",
    "AppPath=C:\\Program Files\\Example\\example.exe",
    "Sig[0].Name=Application Version",
    "Sig[0].Value=1.2.3.4",
  ].join("\r\n");
  await writeFile(
    reportPath,
    Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]),
  );
  const service = createWindowsArtifactsService(process.env);
  try {
    const result = await service.inspectWerReport({ path: reportPath });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error.message);
    const report = result.value.normalized_result as WerReport;
    expect(report.encoding).toBe("utf-16le");
    expect(report.fields[1]).toEqual({
      key: "AppPath",
      value: "C:\\Program Files\\Example\\example.exe",
    });
    expect(report.signatures[0]).toMatchObject({ group: "sig", index: 0 });
  } finally {
    await service.close();
  }
});

it("classifies an undecodable WER artifact as invalid_format input, not unsupported target", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const reportPath = join(root, "Corrupt.wer");
  await writeFile(
    reportPath,
    Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from([0x00, 0xdc])]),
  );
  const service = createWindowsArtifactsService(process.env);
  try {
    const result = await service.inspectWerReport({ path: reportPath });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error._tag).toBe("AnalysisInputError");
    expect(result.error).toMatchObject({
      operation: "inspect_wer_report",
      issues: [
        {
          path: ["path"],
          reason: "invalid_format",
        },
      ],
    });
  } finally {
    await service.close();
  }
});

it("refuses PDB inspection typed when REA_LLVM_PDBUTIL_COMMAND is unset", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const pdbPath = join(root, "application.pdb");
  await writeFile(pdbPath, Buffer.alloc(256, 1));
  const service = createWindowsArtifactsService({});
  try {
    const result = await service.inspectPdbSymbols({ path: pdbPath });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(result.error).toMatchObject({
      providerId: "llvm-pdbutil",
      operation: "inspect_pdb_symbols",
    });
  } finally {
    await service.close();
  }
});

it("dumps a PDB through the fake llvm-pdbutil and keeps source-server streams inert", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const pdbPath = join(root, "application.pdb");
  const pdbBytes = Buffer.concat([
    Buffer.from("Microsoft C/C++ MSF 7.00\r\n", "ascii"),
    Buffer.alloc(256, 0),
  ]);
  await writeFile(pdbPath, pdbBytes);
  const command = await writeFakeLlvmPdbutilDump(
    root,
    REPRESENTATIVE_DUMP_OUTPUT,
  );
  const service = createWindowsArtifactsService({
    REA_LLVM_PDBUTIL_COMMAND: command,
  });
  try {
    const result = await service.inspectPdbSymbols({ path: pdbPath });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error.message);
    const report = result.value.normalized_result as PdbSymbols;
    expect(report.invocation.command).toBe(command);
    expect(report.invocation.arguments.slice(0, 7)).toEqual([
      "dump",
      "-summary",
      "-streams",
      "-modules",
      "-files",
      "-symbols",
      "-publics",
    ]);
    expect(report.artifact.sha256).not.toBe("");
    expect(report.modules).toEqual([
      { index: 0, name: "C:\\src\\main.obj", module_lines: expect.any(Array) },
    ]);
    expect(report.symbols.map(({ kind }) => kind)).toEqual([
      "S_GPROC32",
      "S_PUB32",
    ]);
    expect(report.symbols[0]).toMatchObject({
      segment: 1,
      segment_offset: 0x176,
    });
    expect(report.srcsrv_streams_observed).toEqual(["/src/files/srcsrv.txt"]);
    expect(report.srcsrv_executed).toBe(false);
  } finally {
    await service.close();
  }
});

it("returns a typed refusal when the configured llvm-pdbutil exits nonzero", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const pdbPath = join(root, "application.pdb");
  await writeFile(pdbPath, Buffer.alloc(64, 1));
  const command = await writeFakeLlvmPdbutilScript(
    root,
    "echo 'msf magic' >&2; exit 2",
  );
  const service = createWindowsArtifactsService({
    REA_LLVM_PDBUTIL_COMMAND: command,
  });
  try {
    const result = await service.inspectPdbSymbols({ path: pdbPath });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(result.error.message).toContain("exited nonzero");
  } finally {
    await service.close();
  }
});

it("cancellation before the call is typed and acquires nothing", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const dumpPath = join(root, "example.dmp");
  await writeFile(dumpPath, representativeMinidump().bytes);
  const service = createWindowsArtifactsService(process.env);
  try {
    const controller = new AbortController();
    controller.abort();
    const result = await service.inspectMinidump(
      { path: dumpPath },
      { signal: controller.signal },
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected cancellation");
    expect(result.error._tag).toBe("AnalysisCancelledError");
  } finally {
    await service.close();
  }
});

it("reports malformed dumps and missing files as typed failures", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const garbagePath = join(root, "garbage.dmp");
  await writeFile(garbagePath, Buffer.alloc(64, 7));
  const service = createWindowsArtifactsService(process.env);
  try {
    const garbage = await service.inspectMinidump({ path: garbagePath });
    expect(garbage.ok).toBe(false);
    if (!garbage.ok)
      expect(garbage.error._tag).toBe("AnalysisUnsupportedTargetError");
    const missing = await service.inspectMinidump({
      path: join(root, "absent.dmp"),
    });
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error._tag).toBe("AnalysisInputError");
  } finally {
    await service.close();
  }
});

it("reports the bundled offline lane through the doctor", async () => {
  expect(await inspectWindowsArtifacts()).toMatchObject({
    id: "windows-artifacts",
    configured: true,
    available: true,
    checks: [{ name: "offline-parser", ok: true }],
  });
});

it("reports an unconfigured llvm-pdbutil as a missing analysis engine", async () => {
  expect(await inspectLlvmPdbutil({})).toMatchObject({
    id: "llvm-pdbutil",
    configured: false,
    available: false,
    providerVersion: null,
    checks: [
      {
        name: "configuration",
        ok: false,
        code: "not_configured",
        classification: "missing_analysis_engine",
      },
    ],
  });
});

it("probes the configured llvm-pdbutil's version banner through the doctor", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const command = await writeFakeLlvmPdbutilScript(
    root,
    "echo 'llvm-pdbutil version 19.0.0'",
  );
  expect(
    await inspectLlvmPdbutil({ REA_LLVM_PDBUTIL_COMMAND: command }),
  ).toMatchObject({
    configured: true,
    available: true,
    providerVersion: "llvm-pdbutil version 19.0.0",
    registrationEnvironment: { REA_LLVM_PDBUTIL_COMMAND: command },
    checks: [{ name: "installation", ok: true }],
  });
});

it("reports version-probe and executable failures as config drift", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const failing = await writeFakeLlvmPdbutilScript(root, "exit 3");
  const unresolved = await inspectLlvmPdbutil({
    REA_LLVM_PDBUTIL_COMMAND: failing,
  });
  expect(unresolved.available).toBe(false);
  expect(unresolved.checks[0]).toMatchObject({
    code: "version_unresolved",
    classification: "config_drift",
  });
  const missing = await inspectLlvmPdbutil({
    REA_LLVM_PDBUTIL_COMMAND: join(root, "absent"),
  });
  expect(missing.checks[0]).toMatchObject({
    code: "executable_missing",
    classification: "config_drift",
  });
  const relative = await inspectLlvmPdbutil({
    REA_LLVM_PDBUTIL_COMMAND: "relative/path",
  });
  expect(relative.checks[0]).toMatchObject({
    code: "invalid_path",
  });
});

it("builds a memory64 fixture and parses it through the public service", async () => {
  const root = await createTestTempDirectory("rea-windows-artifacts-");
  const dumpPath = join(root, "memory64.dmp");
  const fixture = buildMinidumpFixture({
    streams: [
      {
        kind: "memory64-list",
        ranges: [{ start: 0x10000n, bytes: 32 }],
      },
    ],
  });
  await writeFile(dumpPath, fixture.bytes);
  const service = createWindowsArtifactsService(process.env);
  try {
    const result = await service.inspectMinidump({ path: dumpPath });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error.message);
    const report = result.value.normalized_result as WindowsMinidump;
    expect(report.memory64_ranges[0]).toEqual({
      start: 0x10000n.toString(10),
      data_size: "32",
      data_offset: expect.stringMatching(/^[0-9]+$/),
    });
  } finally {
    await service.close();
  }
});
