import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { EmuProvider } from "../../../../src/emu/EmuProvider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  writeFakeEmuBridge,
  type FakeEmuBridgeBehavior,
} from "./fakeUnicornBridge.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const providerFor = async (
  behavior: FakeEmuBridgeBehavior,
): Promise<{
  readonly provider: EmuProvider;
  readonly callsPath: string;
  readonly root: string;
  readonly environment: Readonly<Record<string, string>>;
}> => {
  const root = await createTestTempDirectory("rea-emu-");
  const { environment, callsPath } = await writeFakeEmuBridge(root, behavior);
  return {
    provider: new EmuProvider({ environment }),
    callsPath,
    root,
    environment,
  };
};

const CODE = "4889f84883c001c3";

test("emulates a file slice and reports values, digests, and edges only", async () => {
  const { provider, callsPath, root } = await providerFor({});
  const target = join(root, "app.bin");
  const prefix = Buffer.from("HEADERHEADER");
  await writeFile(target, Buffer.concat([prefix, Buffer.from(CODE, "hex")]));
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: {
      arch: "x86_64",
      source: {
        kind: "file",
        path: target,
        offset: prefix.byteLength,
        length: 8,
      },
      code_base: "0x401000",
      args: ["0x1"],
      observe_registers: ["rax", "rdx"],
      observe_memory: [{ address: "0x401000", length: 8 }],
    },
  });
  expect(
    result.ok,
    result.ok ? "" : `${result.error._tag}: ${result.error.message}`,
  ).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.bridge).toMatchObject({
    protocol: 1,
    unicorn_version: "2.1.4",
    keystone_version: "0.9.2",
  });
  expect(value.code).toEqual({
    source: "file",
    path: target,
    offset: prefix.byteLength,
    length: 8,
    sha256: sha256(Buffer.from(CODE, "hex")),
  });
  expect(value.entry).toBe("0x401000");
  expect(value.registers).toEqual([
    { name: "rax", value: "0x2a" },
    { name: "rdx", value: "0x2a" },
  ]);
  expect(value.memory).toEqual([
    { address: "0x401000", length: 8, sha256: "0".repeat(64) },
  ]);
  expect(value.edges).toEqual(["0x401000->0x401000"]);
  expect(value.call_count).toBe(2);
  expect(value.exit).toBe("returned");
  expect(value.coverage).toBe("complete");
  expect(result.value.provider).toMatchObject({
    id: "unicorn",
    version: "2.1.4",
  });
  expect(result.value.locations).toEqual([
    { kind: "artifact-path", path: target },
    {
      kind: "file-offset-range",
      start: prefix.byteLength,
      end: prefix.byteLength + 8,
    },
    { kind: "address", address: "0x401000" },
  ]);
  // The selected instruction bytes never reach Evidence.
  expect(JSON.stringify(result.value)).not.toContain(CODE);
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain(`"code_hex":"${CODE}"`);
  expect(calls).toContain('"max_steps":100000');
  expect(calls).toContain(
    `"code_sha256":"${sha256(Buffer.from(CODE, "hex"))}"`,
  );
  await provider.close();
});

test("emulates caller-supplied hex bytes", async () => {
  const { provider } = await providerFor({});
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: { arch: "arm64", source: { kind: "hex", hex: "c0035fd6" } },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.code).toEqual({
    source: "hex",
    path: null,
    offset: null,
    length: 4,
    sha256: sha256(Buffer.from("c0035fd6", "hex")),
  });
  expect(value.code_base).toBe("0x100000");
  await provider.close();
});

test("refuses an entry point outside the admitted code without starting a job", async () => {
  const { provider, callsPath } = await providerFor({});
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: {
      arch: "x86_64",
      source: { kind: "hex", hex: CODE },
      entry_offset: 8,
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  expect((await readFile(callsPath, "utf8")).trim()).toBe("");
  await provider.close();
});

test("refuses a code window beyond the selected file", async () => {
  const { provider, root } = await providerFor({});
  const target = join(root, "tiny.bin");
  await writeFile(target, Buffer.from(CODE, "hex"));
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: {
      arch: "x86_64",
      source: { kind: "file", path: target, offset: 4, length: 128 },
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  expect(projectAnalysisError(result.error).code).toBe("invalid_request");
  await provider.close();
});

test("refuses big-endian modes Unicorn cannot model", async () => {
  const { provider, callsPath } = await providerFor({});
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: {
      arch: "x86_64",
      endianness: "big",
      source: { kind: "hex", hex: CODE },
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  expect((await readFile(callsPath, "utf8")).trim()).toBe("");
  await provider.close();
});

test("assembles caller source through the same bridge", async () => {
  const { provider, callsPath } = await providerFor({
    assemble: {
      result: {
        bytes_hex: "9048c7c001000000c3",
        size: 10,
        sha256: sha256(Buffer.from("9048c7c001000000c3", "hex")),
        instruction_count: 3,
      },
    },
  });
  const result = await provider.execute({
    operation: "assemble_bytes",
    input: { arch: "x86_64", base_address: "0x401000", assembly: "nop" },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.bytes_hex).toBe("9048c7c001000000c3");
  expect(value.size).toBe(10);
  expect(value.base_address).toBe("0x401000");
  expect(value.assembly).toBe("nop");
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain('"kind":"assemble"');
  expect(calls).toContain('"max_bytes":65536');
  await provider.close();
});

test("marks coverage partial when a job stops at max_steps", async () => {
  const { provider } = await providerFor({
    emulate: {
      result: {
        exit: "max_steps",
        exit_detail: { code: "step_bound", address: null },
        executed_steps: 32,
        coverage: "partial",
      },
    },
  });
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: {
      arch: "x86_64",
      source: { kind: "hex", hex: CODE },
      max_steps: 32,
    },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.exit).toBe("max_steps");
  expect(value.executed_steps).toBe(32);
  expect(value.coverage).toBe("partial");
  expect(result.value.limitations.join(" ")).toContain("stopped at max_steps");
  await provider.close();
});

test("reports a terminal memory fault without assuming a return", async () => {
  const { provider } = await providerFor({
    emulate: {
      result: {
        exit: "invalid_memory_access",
        exit_detail: { code: "read_unmapped", address: null },
        coverage: "partial",
      },
    },
  });
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: { arch: "x86_64", source: { kind: "hex", hex: CODE } },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.exit).toBe("invalid_memory_access");
  expect(value.exit_detail).toEqual({
    code: "read_unmapped",
    address: null,
  });
  expect(value.coverage).toBe("partial");
  await provider.close();
});

test("assembles on an interpreter that carries Keystone but not Unicorn", async () => {
  const { provider } = await providerFor({ unicornVersion: null });
  const result = await provider.execute({
    operation: "assemble_bytes",
    input: { arch: "x86_64", assembly: "ret" },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  if (!result.ok) return;
  expect(result.value.provider).toMatchObject({
    id: "unicorn",
    version: null,
  });
  expect((result.value.result as Record<string, unknown>).bridge).toMatchObject(
    { unicorn_version: null, keystone_version: "0.9.2" },
  );
  await provider.close();
});

test("reports a missing Unicorn import as an unavailable capability", async () => {
  const { provider } = await providerFor({
    emulate: {
      error: {
        code: "missing_dependency",
        message: "the selected interpreter cannot import unicorn",
      },
    },
  });
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: { arch: "x86_64", source: { kind: "hex", hex: CODE } },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("Install Unicorn 2.1.x");
  await provider.close();
});

test("rejects an answer that is not one JSON frame", async () => {
  const { provider } = await providerFor({ malformed: "not a frame" });
  const result = await provider.execute({
    operation: "assemble_bytes",
    input: { arch: "x86_64", assembly: "ret" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
  await provider.close();
});

test("rejects a frame above the transport budget", async () => {
  const { provider } = await providerFor({ oversizedBytes: 1_100_000 });
  const result = await provider.execute({
    operation: "assemble_bytes",
    input: { arch: "x86_64", assembly: "ret" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  expect(result.error.diagnostics).toMatchObject({
    max_frame_bytes: 1_048_576,
  });
  await provider.close();
});

test("reports a sidecar that exits before answering", async () => {
  const { provider } = await providerFor({ exitBeforeAnswer: 7 });
  const result = await provider.execute({
    operation: "assemble_bytes",
    input: { arch: "x86_64", assembly: "ret" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.diagnostics).toMatchObject({ exit_code: 7 });
  await provider.close();
});

test("refuses emulated code other than the bytes REA selected", async () => {
  const { provider } = await providerFor({
    emulate: {
      result: {
        code: {
          source: "hex",
          path: null,
          offset: null,
          length: 5,
          sha256: "1".repeat(64),
        },
      },
    },
  });
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: { arch: "x86_64", source: { kind: "hex", hex: CODE } },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("stops a job that outlives its deadline", async () => {
  const { provider } = await providerFor({ emulate: { delayMs: 30_000 } });
  const started = Date.now();
  const result = await provider.execute({
    operation: "emulate_function_isolated",
    input: {
      arch: "x86_64",
      source: { kind: "hex", hex: CODE },
      timeout_ms: 1,
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisOutputError");
  expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
  expect(result.error.diagnostics).toMatchObject({ timeout_ms: 1 });
  // The caller's deadline is extended only by the bounded stop grace.
  expect(Date.now() - started).toBeLessThan(10_000);
  await provider.close();
});

test("cancels a running job cooperatively", async () => {
  const { provider } = await providerFor({ emulate: { delayMs: 30_000 } });
  const controller = new AbortController();
  const pending = provider.execute(
    {
      operation: "emulate_function_isolated",
      input: { arch: "x86_64", source: { kind: "hex", hex: CODE } },
    },
    { signal: controller.signal },
  );
  setTimeout(() => controller.abort(new Error("caller cancelled")), 50);
  const result = await pending;
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisCancelledError");
  await provider.close();
});

test("never starts a job for an already-cancelled caller", async () => {
  const { provider, callsPath } = await providerFor({});
  const controller = new AbortController();
  controller.abort(new Error("already cancelled"));
  const result = await provider.execute(
    {
      operation: "emulate_function_isolated",
      input: { arch: "x86_64", source: { kind: "hex", hex: CODE } },
    },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisCancelledError");
  expect((await readFile(callsPath, "utf8")).trim()).toBe("");
  await provider.close();
});

test("refuses plainly when no interpreter and bridge are selected", async () => {
  const provider = new EmuProvider({ environment: {} });
  const result = await provider.execute({
    operation: "assemble_bytes",
    input: { arch: "x86_64", assembly: "ret" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_UNICORN_PYTHON");
  const availability = provider.inspectAvailability();
  expect(availability).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await provider.close();
});

test("reports the selected bridge without starting it", async () => {
  const { provider, callsPath } = await providerFor({});
  const availability = provider.inspectAvailability();
  expect(availability).toMatchObject({
    status: "available",
    code: null,
    diagnostics: { probe: "selection_only" },
  });
  expect((await readFile(callsPath, "utf8")).trim()).toBe("");
  await provider.close();
});
