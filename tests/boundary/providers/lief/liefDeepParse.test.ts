import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { expect, it } from "vitest";

import { createLiefService } from "../../../../src/composition/lief.js";
import {
  LIEF_BRIDGE_DIR_ENV,
  LIEF_BRIDGE_FILE_NAME,
  LIEF_COMMAND_ENV,
  LIEF_IMPORT_REMEDIATION,
} from "../../../../src/domain/lief/liefLimits.js";
import type { BinaryDeepReport } from "../../../../src/domain/lief/binaryDeep.js";
import type { PdbDwarfInfoReport } from "../../../../src/domain/lief/pdbDwarfInfo.js";
import { inspectLiefProvider } from "../../../../src/lief/LiefDoctor.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const run = promisify(execFile);

const ELF_BYTES = Buffer.concat([
  Buffer.from("\u007fELF", "binary"),
  Buffer.alloc(64, 0x41),
]);

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
  structure_summary: {
    section_count: 2,
    segment_count: 1,
    linked_library_count: 1,
  },
  dynamic: {
    interpreter: "/lib64/ld-linux-x86-64.so.2",
    soname: null,
    needed: ["libc.so.6"],
    rpath: [],
    runpath: [],
    entries: [],
  },
  macho: null,
  pe: null,
  debug_sources: {
    dwarf: { present: false, sections: [] },
    pdb_reference: null,
  },
  truncated: {
    architectures: false,
    dynamic_entries: false,
    libraries: false,
    load_commands: false,
    data_directories: false,
    debug_entries: false,
    debug_sections: false,
  },
  complete: true,
  limitations: [],
} as const;

const BRIDGE_FACTS = {
  lief_version: "0.16.0",
  python_version: "3.13.1",
  capabilities: { dwarf: true, pdb: true, fat: true },
} as const;

const reportFrame = (operation: string, report: unknown): string =>
  `${JSON.stringify({
    kind: "lief_report",
    protocol: 1,
    operation,
    bridge: BRIDGE_FACTS,
    report,
  })}\n`;

/** A caller-selected interpreter stand-in that prints one scripted frame. */
const writeFakeInterpreter = async (
  directory: string,
  frame: string,
): Promise<string> => {
  const path = join(directory, "python3");
  await writeFile(
    path,
    `#!/bin/sh\ncat <<'REA_FAKE_LIEF_EOF'\n${frame}REA_FAKE_LIEF_EOF\n`,
  );
  await chmod(path, 0o755);
  return path;
};

/** A fake interpreter body that ignores the frame and runs its own shell body. */
const writeScriptedInterpreter = async (
  directory: string,
  body: string,
): Promise<string> => {
  const path = join(directory, "python3");
  await writeFile(path, `#!/bin/sh\n${body}\n`);
  await chmod(path, 0o755);
  return path;
};

const selectedLane = async (
  command: string,
  directory: string,
): Promise<Readonly<NodeJS.ProcessEnv>> => {
  await writeFile(join(directory, LIEF_BRIDGE_FILE_NAME), "# bridge\n");
  return { [LIEF_COMMAND_ENV]: command, [LIEF_BRIDGE_DIR_ENV]: directory };
};

it("reports a deep structure through the composed service and Evidence", async () => {
  const root = await createTestTempDirectory("rea-lief-deep-");
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  const environment = await selectedLane(
    await writeFakeInterpreter(
      root,
      reportFrame("inspect_binary_deep", ELF_REPORT),
    ),
    root,
  );
  const service = createLiefService(environment);
  try {
    const result = await service.inspectBinaryDeep({ path: artifact });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error.message);
    const report = result.value.normalized_result as BinaryDeepReport;
    const sha256 = createHash("sha256").update(ELF_BYTES).digest("hex");
    expect(report.artifact).toEqual({
      path: artifact,
      sha256,
      bytes: ELF_BYTES.length,
    });
    expect(report.dynamic?.needed).toEqual(["libc.so.6"]);
    expect(result.value.evidence_id.startsWith("ev_")).toBe(true);
    expect(result.value.subject?.digest).toEqual({ sha256 });
    expect(report.delegated_facts.map(({ tool }) => tool)).toContain(
      "inspect_binary_layout",
    );
  } finally {
    await service.close();
  }
});

it("refuses a malformed frame instead of reporting partial structure", async () => {
  const root = await createTestTempDirectory("rea-lief-deep-");
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  const environment = await selectedLane(
    await writeScriptedInterpreter(root, "printf 'not json\\n'"),
    root,
  );
  const service = createLiefService(environment);
  try {
    const result = await service.inspectBinaryDeep({ path: artifact });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error._tag).toBe("AnalysisOutputError");
  } finally {
    await service.close();
  }
});

it("carries the bridge's own typed refusal through with remediation", async () => {
  const root = await createTestTempDirectory("rea-lief-deep-");
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  const environment = await selectedLane(
    await writeFakeInterpreter(
      root,
      `${JSON.stringify({
        kind: "lief_error",
        protocol: 1,
        code: "lief_missing",
        message:
          "the selected interpreter cannot import LIEF (ModuleNotFoundError)",
      })}\n`,
    ),
    root,
  );
  const service = createLiefService(environment);
  try {
    const result = await service.inspectBinaryDeep({ path: artifact });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error).toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      providerId: "lief",
      remediationAction: LIEF_IMPORT_REMEDIATION,
    });
  } finally {
    await service.close();
  }
});

it("refuses an oversized frame rather than clipping it", async () => {
  const root = await createTestTempDirectory("rea-lief-deep-");
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  const environment = await selectedLane(
    await writeScriptedInterpreter(
      root,
      `head -c 8388609 /dev/zero | tr '\\0' 'x'`,
    ),
    root,
  );
  const service = createLiefService(environment);
  try {
    const result = await service.inspectBinaryDeep({ path: artifact });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error._tag).toBe("AnalysisResourceConstraintError");
    expect(result.error).toMatchObject({ resource: "memory" });
  } finally {
    await service.close();
  }
});

it("cancels an in-flight run and reports cancellation", async () => {
  const root = await createTestTempDirectory("rea-lief-deep-");
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  const environment = await selectedLane(
    await writeScriptedInterpreter(root, "sleep 30"),
    root,
  );
  const service = createLiefService(environment);
  const controller = new AbortController();
  try {
    const pending = service.inspectBinaryDeep(
      { path: artifact },
      { signal: controller.signal },
    );
    setTimeout(() => controller.abort(new Error("stop")), 150);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error._tag).toBe("AnalysisCancelledError");
  } finally {
    controller.abort();
    await service.close();
  }
});

it("refuses typed before any run when the lane is unconfigured", async () => {
  const root = await createTestTempDirectory("rea-lief-deep-");
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  const service = createLiefService({});
  try {
    const deep = await service.inspectBinaryDeep({ path: artifact });
    expect(deep.ok).toBe(false);
    if (deep.ok) throw new Error("expected refusal");
    expect(deep.error).toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      providerId: "lief",
    });
    const debug = await service.extractPdbDwarfInfo({ path: artifact });
    expect(debug.ok).toBe(false);
  } finally {
    await service.close();
  }
});

it("refuses a selected directory that does not hold the bridge script", async () => {
  const root = await createTestTempDirectory("rea-lief-deep-");
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  const command = await writeFakeInterpreter(
    root,
    reportFrame("inspect_binary_deep", ELF_REPORT),
  );
  const service = createLiefService({
    [LIEF_COMMAND_ENV]: command,
    [LIEF_BRIDGE_DIR_ENV]: root,
  });
  try {
    const result = await service.inspectBinaryDeep({ path: artifact });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected refusal");
    expect(result.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(result.error.message).toContain(LIEF_BRIDGE_FILE_NAME);
  } finally {
    await service.close();
  }
});

it("reports debug-info lookups with found and not_found outcomes", async () => {
  const root = await createTestTempDirectory("rea-lief-deep-");
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  const debugReport = {
    artifact_kind: "elf",
    debug_sources: {
      dwarf: {
        present: true,
        sections: [{ name: ".debug_info", size: 256 }],
        compilation_unit_count: 1,
        function_count: 1,
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
        query: { kind: "address", address: 0x401000 },
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
    ],
    truncated: { queries: false, matches: false, dwarf_functions: false },
    complete: true,
    limitations: [],
  };
  const environment = await selectedLane(
    await writeFakeInterpreter(
      root,
      reportFrame("extract_pdb_dwarf_info", debugReport),
    ),
    root,
  );
  const service = createLiefService(environment);
  try {
    const result = await service.extractPdbDwarfInfo({
      path: artifact,
      queries: [{ kind: "address", address: 0x401000 }],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error.message);
    const report = result.value.normalized_result as PdbDwarfInfoReport;
    expect(report.queries[0]?.outcome).toBe("found");
    expect(report.queries[0]?.matches[0]?.name).toBe("main");
  } finally {
    await service.close();
  }
});

it("reports doctor readiness and refuses a release outside the pinned range", async () => {
  const readyRoot = await createTestTempDirectory("rea-lief-doctor-");
  await writeFile(join(readyRoot, LIEF_BRIDGE_FILE_NAME), "# bridge\n");
  const ready = await inspectLiefProvider({
    [LIEF_COMMAND_ENV]: await writeScriptedInterpreter(
      readyRoot,
      `printf '{"version": "0.16.0"}\\n'`,
    ),
    [LIEF_BRIDGE_DIR_ENV]: readyRoot,
  });
  expect(ready).toMatchObject({
    id: "lief",
    configured: true,
    available: true,
    providerVersion: "0.16.0",
  });

  const oldRoot = await createTestTempDirectory("rea-lief-doctor-");
  await writeFile(join(oldRoot, LIEF_BRIDGE_FILE_NAME), "# bridge\n");
  const unsupported = await inspectLiefProvider({
    [LIEF_COMMAND_ENV]: await writeScriptedInterpreter(
      oldRoot,
      `printf '{"version": "0.9.0"}\\n'`,
    ),
    [LIEF_BRIDGE_DIR_ENV]: oldRoot,
  });
  expect(unsupported.available).toBe(false);
  expect(unsupported.checks[0]).toMatchObject({
    code: "version_unsupported",
    classification: "config_drift",
  });

  const unconfigured = await inspectLiefProvider({});
  expect(unconfigured).toMatchObject({
    configured: false,
    available: false,
  });
  expect(unconfigured.checks[0]?.code).toBe("not_configured");
});

const python = async (): Promise<string | undefined> => {
  for (const candidate of ["/usr/bin/python3", "/usr/local/bin/python3"]) {
    try {
      await run(candidate, ["-c", "import sys; print(sys.version_info[0])"]);
      return candidate;
    } catch {
      continue;
    }
  }
  return undefined;
};

it("exercises the shipped bridge script end to end with a fake LIEF module", async () => {
  const interpreter = await python();
  if (interpreter === undefined) return;
  const root = await createTestTempDirectory("rea-lief-bridge-");
  const site = join(root, "site");
  await mkdir(site, { recursive: true });
  await writeFile(
    join(site, "lief.py"),
    [
      "__version__ = '0.16.0'",
      "",
      "class _Obj:",
      "    def __init__(self, **values):",
      "        self.__dict__.update(values)",
      "",
      "class _Name:",
      "    def __init__(self, name):",
      "        self.name = name",
      "",
      "def _section(name, size):",
      "    return _Obj(name=name, size=size)",
      "",
      "def _function(name, address, size):",
      "    return _Obj(name=name, address=address, size=size)",
      "",
      "def parse(_path):",
      "    header = _Obj(",
      "        identity_class=_Name('CLASS64'),",
      "        identity_data=_Name('LSB'),",
      "        machine=_Name('X86_64'),",
      "    )",
      "    return _Obj(",
      "        header=header,",
      "        entrypoint=0x401000,",
      "        imagebase=0x400000,",
      "        has_interpreter=True,",
      "        interpreter='/lib64/ld-linux-x86-64.so.2',",
      "        soname=None,",
      "        libraries=['libc.so.6'],",
      "        has_dynamic_entries=False,",
      "        dynamic_entries=[],",
      "        sections=[_section('.text', 64), _section('.debug_info', 256)],",
      "        segments=[_Obj()],",
      "    )",
      "",
      "class DWARF:",
      "    @staticmethod",
      "    def from_binary(_binary):",
      "        unit = _Obj(name='main.c', functions=[_function('main', 0x401000, 0x40)])",
      "        return _Obj(compilation_units=[unit])",
      "",
    ].join("\n"),
  );
  const artifact = join(root, "example.elf");
  await writeFile(artifact, ELF_BYTES);
  await writeFile(
    join(root, LIEF_BRIDGE_FILE_NAME),
    await import("node:fs/promises").then(({ readFile }) =>
      readFile(
        new URL("../../../../bridge/lief/lief_bridge.py", import.meta.url),
        "utf8",
      ),
    ),
  );
  const environment = {
    [LIEF_COMMAND_ENV]: interpreter,
    [LIEF_BRIDGE_DIR_ENV]: root,
    PYTHONPATH: site,
    PYTHONDONTWRITEBYTECODE: "1",
  } as const;
  const service = createLiefService(environment);
  try {
    const deep = await service.inspectBinaryDeep({ path: artifact });
    expect(deep.ok).toBe(true);
    if (!deep.ok) throw new Error(deep.error.message);
    const report = deep.value.normalized_result as BinaryDeepReport;
    expect(report.format).toBe("elf");
    expect(report.bridge.lief_version).toBe("0.16.0");
    expect(report.dynamic?.interpreter).toBe("/lib64/ld-linux-x86-64.so.2");
    const debug = await service.extractPdbDwarfInfo({
      path: artifact,
      queries: [{ kind: "symbol", name: "main" }],
    });
    expect(debug.ok).toBe(true);
    if (!debug.ok) throw new Error(debug.error.message);
    const lookups = debug.value.normalized_result as PdbDwarfInfoReport;
    expect(lookups.queries[0]?.outcome).toBe("found");
    expect(lookups.queries[0]?.matches[0]?.compilation_unit).toBe("main.c");
  } finally {
    await service.close();
  }
});
