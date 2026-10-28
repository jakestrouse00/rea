import { expect, test } from "vitest";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { AnalysisSettingsReader } from "../../../../src/domain/analysisSettings.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { AngrProvider } from "../../../../src/angr/AngrProvider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  writeFakeAngrBridge,
  type FakeAngrBridgeBehavior,
} from "./fakeAngrBridge.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const BINARY = Buffer.from("7f454c46firmware-bytes", "utf8");

interface Harness {
  readonly provider: AngrProvider;
  readonly callsPath: string;
  readonly target: string;
  readonly root: string;
  readonly environment: Readonly<Record<string, string>>;
}

const providerFor = async (
  behavior: FakeAngrBridgeBehavior = {},
  options: {
    readonly settings?: AnalysisSettingsReader;
    readonly environment?: Readonly<Record<string, string>>;
  } = {},
): Promise<Harness> => {
  const root = await createTestTempDirectory("rea-angr-");
  const { environment, callsPath } = await writeFakeAngrBridge(root, behavior);
  const target = join(root, "firmware.bin");
  await writeFile(target, BINARY);
  return {
    provider: new AngrProvider({
      environment: { ...environment, ...options.environment },
      ...(options.settings === undefined ? {} : { settings: options.settings }),
    }),
    callsPath,
    target,
    root,
    environment,
  };
};

const settingsWith =
  (timeoutMs: number): AnalysisSettingsReader =>
  () => ({
    revision: 1,
    overrides: { "angr.operation_timeout_ms": timeoutMs },
  });

const findPaths = (target: string) => ({
  operation: "find_paths_to_target" as const,
  input: {
    path: target,
    entry: "0x401000",
    stdin_bytes: 8,
    assertions: [
      {
        operand: { kind: "stdin" as const, offset: 0, width_bytes: 1 },
        relation: "eq" as const,
        value: "0x5a",
      },
    ],
    find_addresses: ["0x4010a0"],
    max_paths: 1,
  },
});

test("solves one path and reports conditions and model values as digests", async () => {
  const { provider, callsPath, target } = await providerFor();
  const result = await provider.execute(findPaths(target));
  expect(
    result.ok,
    result.ok ? "" : `${result.error._tag}: ${result.error.message}`,
  ).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.bridge).toMatchObject({ protocol: 1, angr_version: "9.2.4" });
  expect(value.target).toEqual({
    path: target,
    entry: "0x401000",
    sha256: sha256(BINARY),
  });
  expect(value.reachable).toBe(true);
  expect(value.termination).toBe("find_hit");
  expect(value.assertion_count).toBe(1);
  expect(value.values_redacted).toBe(true);
  const paths = value.paths as Record<string, unknown>[];
  expect(paths[0]).toMatchObject({
    address: "0x4010a0",
    found: true,
    conditions: [
      {
        index: 0,
        depth: 0,
        kind: "operation",
        op: "__eq__",
        bits: 1,
        operand: null,
        constant_sha256: "0".repeat(64),
      },
      {
        index: 1,
        depth: 1,
        kind: "symbol",
        op: "bvs",
        bits: 64,
        operand: "rea_stdin",
        constant_sha256: null,
      },
    ],
    model: [{ name: "rea_stdin", bits: 64, value_sha256: expect.any(String) }],
  });
  // The caller's asserted byte never reaches Evidence.
  expect(JSON.stringify(result.value)).not.toContain("0x5a");
  expect(result.value.provider).toMatchObject({ id: "angr", version: "9.2.4" });
  expect(result.value.locations).toEqual([
    { kind: "artifact-path", path: target },
    { kind: "address", address: "0x401000" },
  ]);
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain('"kind":"find_paths"');
  expect(calls).toContain(`"binary_sha256":"${sha256(BINARY)}"`);
  expect(calls).toContain('"stdin_bytes":8');
  expect(calls).toContain('"value":"0x5a"');
  await provider.close();
});

test("applies the runtime deadline setting when the request names none", async () => {
  const { provider, callsPath, target } = await providerFor(
    {},
    {
      settings: settingsWith(45_000),
    },
  );
  const result = await provider.execute(findPaths(target));
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain('"timeout_ms":45000');
  await provider.close();
});

test("lets an explicit request deadline win over the setting", async () => {
  const { provider, callsPath, target } = await providerFor(
    {},
    {
      settings: settingsWith(45_000),
    },
  );
  const request = findPaths(target);
  const result = await provider.execute({
    ...request,
    input: { ...request.input, timeout_ms: 5_000 },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain('"timeout_ms":5000');
  expect(calls).not.toContain('"timeout_ms":45000');
  await provider.close();
});

test("carries a deadline past the old bridge ceiling to the sidecar", async () => {
  const { provider, callsPath, target } = await providerFor();
  const request = findPaths(target);
  const result = await provider.execute({
    ...request,
    input: { ...request.input, timeout_ms: 900_000 },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  expect(await readFile(callsPath, "utf8")).toContain('"timeout_ms":900000');
  await provider.close();
});

test("reports an exploration's counts and address coverage", async () => {
  const { provider, target } = await providerFor();
  const result = await provider.execute({
    operation: "run_symbolic_function_exploration",
    input: {
      path: target,
      entry: "0x401000",
      stdin_bytes: 16,
      find_addresses: ["0x4010a0"],
      max_states: 8,
    },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value).toMatchObject({
    termination: "find_hit",
    explored_states: 6,
    found_states: 1,
    visited_blocks: ["0x401000", "0x401010"],
    visited_blocks_truncated: false,
    coverage: "complete",
  });
  expect(result.value.limitations.join(" ")).toContain(
    "not a count of the function's real control-flow paths",
  );
  await provider.close();
});

test("keeps visited blocks when an exploration finds nothing", async () => {
  const { provider, target } = await providerFor({
    explore_function: {
      result: {
        termination: "deadended",
        found: [],
        found_states: 0,
        deadended_states: 1,
        visited_blocks: ["0x401000", "0x401010"],
        coverage: "complete",
      },
    },
  });
  const result = await provider.execute({
    operation: "run_symbolic_function_exploration",
    input: {
      path: target,
      entry: "0x401000",
      find_addresses: ["0x4010a0"],
    },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value).toMatchObject({
    termination: "deadended",
    found_states: 0,
    visited_blocks: ["0x401000", "0x401010"],
    visited_blocks_truncated: false,
    coverage: "complete",
  });
  await provider.close();
});

test("recovers a control-flow graph as addresses for cross-checking", async () => {
  const { provider, target } = await providerFor();
  const result = await provider.execute({
    operation: "recover_control_flow_angr",
    input: { path: target },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.functions).toEqual([{ address: "0x401000", block_count: 2 }]);
  expect(value.blocks).toEqual([
    { address: "0x401000", size: 4, successors: ["0x401004"] },
    { address: "0x401004", size: 4, successors: [] },
  ]);
  expect(value.edge_count).toBe(1);
  expect(value.target).toEqual({
    path: target,
    entry: null,
    sha256: sha256(BINARY),
  });
  expect(result.value.locations).toEqual([
    { kind: "artifact-path", path: target },
  ]);
  expect(result.value.limitations.join(" ")).toContain(
    "cross-check them against rizin or Ghidra",
  );
  await provider.close();
});

test("marks coverage partial when a job stops at its own bound", async () => {
  const { provider, target } = await providerFor({
    find_paths: {
      result: {
        reachable: false,
        termination: "step_bound",
        paths: [],
        paths_truncated: false,
        coverage: "partial",
      },
    },
  });
  const result = await provider.execute(findPaths(target));
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.termination).toBe("step_bound");
  expect(value.coverage).toBe("partial");
  expect(result.value.limitations.join(" ")).toContain(
    "stopped at its step bound",
  );
  await provider.close();
});

test("refuses bytes other than the artifact REA digested", async () => {
  const { provider, target } = await providerFor({
    find_paths: { result: { target: { sha256: "1".repeat(64) } } },
  });
  const result = await provider.execute(findPaths(target));
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
  await provider.close();
});

test("refuses a frame that breaks the declared contract", async () => {
  const { provider, target } = await providerFor({
    find_paths: { result: { values_redacted: false } },
  });
  const result = await provider.execute(findPaths(target));
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("rejects an answer that is not one JSON frame", async () => {
  const { provider, target } = await providerFor({ malformed: "not a frame" });
  const result = await provider.execute(findPaths(target));
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("rejects a frame above the transport budget", async () => {
  const { provider, target } = await providerFor({ oversizedBytes: 1_100_000 });
  const result = await provider.execute(findPaths(target));
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  expect(result.error.diagnostics).toMatchObject({
    max_frame_bytes: 1_048_576,
  });
  await provider.close();
});

test("reports a sidecar that exits before answering", async () => {
  const { provider, target } = await providerFor({ exitBeforeAnswer: 7 });
  const result = await provider.execute(findPaths(target));
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.diagnostics).toMatchObject({ exit_code: 7 });
  await provider.close();
});

test("reports a missing angr import as an unavailable capability", async () => {
  const { provider, target } = await providerFor({
    find_paths: {
      error: {
        code: "missing_dependency",
        message: "the selected interpreter cannot import angr",
      },
    },
  });
  const result = await provider.execute(findPaths(target));
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("Install angr 9.2.x");
  await provider.close();
});

test("reports an unpinned engine as an unavailable capability", async () => {
  const { provider, target } = await providerFor({
    recover_cfg: {
      error: {
        code: "version_unsupported",
        message: "angr 9.3.0 is not the pinned 9.2.x release",
      },
    },
  });
  const result = await provider.execute({
    operation: "recover_control_flow_angr",
    input: { path: target },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  await provider.close();
});

test("stops a job that outlives its deadline", async () => {
  const { provider, target } = await providerFor({
    find_paths: { delayMs: 30_000 },
  });
  const started = Date.now();
  const request = findPaths(target);
  const result = await provider.execute({
    ...request,
    input: { ...request.input, timeout_ms: 1 },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisOutputError");
  expect(result.error.diagnostics).toMatchObject({ timeout_ms: 1 });
  expect(Date.now() - started).toBeLessThan(10_000);
  await provider.close();
});

test("cancels a running job cooperatively", async () => {
  const { provider, target } = await providerFor({
    find_paths: { delayMs: 30_000 },
  });
  const controller = new AbortController();
  const pending = provider.execute(findPaths(target), {
    signal: controller.signal,
  });
  setTimeout(() => controller.abort(new Error("caller cancelled")), 50);
  const result = await pending;
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisCancelledError");
  await provider.close();
});

test("never starts a job for an already-cancelled caller", async () => {
  const { provider, callsPath, target } = await providerFor();
  const controller = new AbortController();
  controller.abort(new Error("already cancelled"));
  const result = await provider.execute(findPaths(target), {
    signal: controller.signal,
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisCancelledError");
  expect((await readFile(callsPath, "utf8")).trim()).toBe("");
  await provider.close();
});

test("refuses an artifact that is not one readable regular file", async () => {
  const { provider, callsPath, root } = await providerFor();
  const directory = join(root, "not-a-file");
  await mkdir(directory, { recursive: true });
  const result = await provider.execute(findPaths(directory));
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  expect((await readFile(callsPath, "utf8")).trim()).toBe("");
  await provider.close();
});

test("refuses plainly when no interpreter and bridge are selected", async () => {
  const provider = new AngrProvider({ environment: {} });
  const result = await provider.execute({
    operation: "recover_control_flow_angr",
    input: { path: "/nonexistent/firmware.bin" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_ANGR_PYTHON");
  expect(provider.inspectAvailability()).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await provider.close();
});

test("refuses a concurrency cap outside its stated range", async () => {
  const { provider, target } = await providerFor(
    {},
    {
      environment: { REA_ANGR_JOBS: "0" },
    },
  );
  const result = await provider.execute(findPaths(target));
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_ANGR_JOBS");
  await provider.close();
});

test("reports the selected bridge and bounds without starting it", async () => {
  const { provider, callsPath } = await providerFor(
    {},
    {
      environment: { REA_ANGR_JOBS: "2" },
    },
  );
  const availability = provider.inspectAvailability();
  expect(availability).toMatchObject({
    status: "available",
    code: null,
    diagnostics: {
      probe: "selection_only",
      admitted_jobs: 2,
      pinned_angr_version: "9.2.x",
      angr_version_unverified: true,
    },
  });
  expect((await readFile(callsPath, "utf8")).trim()).toBe("");
  await provider.close();
});
