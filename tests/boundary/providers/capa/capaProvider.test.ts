import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { CapaProvider } from "../../../../src/capa/CapaProvider.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { writeFakeCapa, type FakeCapaBehavior } from "./fakeCapa.js";

const providerFor = async (
  behavior: FakeCapaBehavior,
): Promise<{
  readonly provider: CapaProvider;
  readonly launcher: string;
  readonly callsPath: string;
  readonly root: string;
}> => {
  const root = await createTestTempDirectory("rea-capa-");
  const { launcher, callsPath } = await writeFakeCapa(root, behavior);
  return {
    provider: new CapaProvider({ environment: { REA_CAPA_COMMAND: launcher } }),
    launcher,
    callsPath,
    root,
  };
};

const resultOf = async (
  provider: CapaProvider,
  input: Parameters<CapaProvider["execute"]>[0]["input"],
): Promise<Record<string, unknown>> => {
  const result = await provider.execute({
    operation: "analyze_binary_capabilities",
    input,
  });
  if (!result.ok) throw new Error(result.error.message);
  return result.value.result as Record<string, unknown>;
};

const analysisFixture = {
  meta: {
    analysis: { format: "pe", arch: "amd64", os: "windows" },
  },
  rules: {
    "write process memory": {
      meta: {
        name: "write process memory",
        namespace: "host-interaction/process",
        scopes: { static: "function" },
        authors: ["analyst"],
        attack: [
          { id: "T1055", parts: ["Defense Evasion", "Process Injection"] },
        ],
        mbc: [{ id: "C0003", parts: ["Process", "Write Process Memory"] }],
      },
      matches: {
        "0x401000": { success: true },
        "0x401200": { success: true },
      },
    },
    "create process": {
      meta: { name: "create process", namespace: "host-interaction/process" },
      matches: ["0x402000"],
    },
  },
};

test("parses a capa document into a structural rule inventory", async () => {
  const { provider, callsPath, root } = await providerFor({
    analysis: analysisFixture,
  });
  const target = join(root, "sample.exe");
  await writeFile(target, "MZ-FIXTURE");
  const result = await resultOf(provider, { path: target });
  expect(result.client).toEqual({
    command: expect.any(String),
    version: "9.0.0",
  });
  expect(result.bytes).toBe("MZ-FIXTURE".length);
  expect(result.sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(result.format).toBe("pe");
  expect(result.arch).toBe("amd64");
  expect(result.os).toBe("windows");
  expect(result.rule_count).toBe(2);
  expect(result.match_count).toBe(3);
  expect(result.coverage).toBe("complete");
  expect(result.rules).toEqual([
    {
      id: "create process",
      namespace: "host-interaction/process",
      scope: null,
      authors: [],
      attack: [],
      mbc: [],
      match_count: 1,
      locations: ["0x402000"],
    },
    {
      id: "write process memory",
      namespace: "host-interaction/process",
      scope: "static",
      authors: ["analyst"],
      attack: [
        {
          id: "T1055",
          tactic: "Defense Evasion",
          technique: "Process Injection",
        },
      ],
      mbc: [
        { id: "C0003", objective: "Process", behavior: "Write Process Memory" },
      ],
      match_count: 2,
      locations: ["0x401000", "0x401200"],
    },
  ]);
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain(`["-j","${target}"]`);
});

test("passes an explicit backend override to capa", async () => {
  const { provider, callsPath, root } = await providerFor({
    analysis: analysisFixture,
  });
  const target = join(root, "sample.exe");
  await writeFile(target, "MZ-FIXTURE");
  await resultOf(provider, { path: target, backend: "ghidra" });
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain(`["-j","-b","ghidra","${target}"]`);
});

test("refuses plainly when no capa binary is selected", async () => {
  const provider = new CapaProvider({ environment: {} });
  const result = await provider.execute({
    operation: "analyze_binary_capabilities",
    input: { path: "/does/not/matter.exe" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_CAPA_COMMAND");
  await provider.close();
});

test("refuses a launcher whose version probe fails", async () => {
  const root = await createTestTempDirectory("rea-capa-badver-");
  const { launcher } = await writeFakeCapa(root, { version: { exit: 3 } });
  const provider = new CapaProvider({
    environment: { REA_CAPA_COMMAND: launcher },
  });
  const target = join(root, "sample.exe");
  await writeFile(target, "MZ-FIXTURE");
  const result = await provider.execute({
    operation: "analyze_binary_capabilities",
    input: { path: target },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  await provider.close();
});

test("rejects a document that is not a capa rule inventory without partial success", async () => {
  const { provider, root } = await providerFor({ analysis: { rules: null } });
  const target = join(root, "sample.exe");
  await writeFile(target, "MZ-FIXTURE");
  const result = await provider.execute({
    operation: "analyze_binary_capabilities",
    input: { path: target },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("counts unrecognized rule rows and marks the inventory partial", async () => {
  const { provider, root } = await providerFor({
    analysis: {
      rules: {
        recognized: { meta: { name: "recognized" }, matches: { "0x1": {} } },
        broken: "not-a-rule",
      },
    },
  });
  const target = join(root, "sample.exe");
  await writeFile(target, "MZ-FIXTURE");
  const result = await resultOf(provider, { path: target });
  expect(result.rule_count).toBe(1);
  expect(result.unparsed_entries).toBe(1);
  expect(result.coverage).toBe("partial");
  await provider.close();
});

test("reports the capa client as available only after a version probe", async () => {
  const { provider } = await providerFor({});
  const available = await provider.inspectAvailability();
  expect(available.status).toBe("available");
  expect(available.diagnostics).toMatchObject({ version: "9.0.0" });
  await provider.close();

  const unconfigured = new CapaProvider({ environment: {} });
  const unavailable = await unconfigured.inspectAvailability();
  expect(unavailable).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await unconfigured.close();
});

test("keeps caller cancellation typed before any process starts", async () => {
  const { provider } = await providerFor({});
  const controller = new AbortController();
  controller.abort(new Error("caller window closed"));
  const result = await provider.execute(
    {
      operation: "analyze_binary_capabilities",
      input: { path: "/tmp/fixture.exe" },
    },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisCancelledError");
  await provider.close();
});

test("rejects a missing target without starting capa", async () => {
  const { provider, callsPath, root } = await providerFor({
    analysis: analysisFixture,
  });
  const result = await provider.execute({
    operation: "analyze_binary_capabilities",
    input: { path: join(root, "absent.exe") },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  await provider.close();
  expect(await readFile(callsPath, "utf8")).not.toContain('"-j"');
});
