import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { View8Provider } from "../../../../src/javascript/v8/View8Provider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { cachedDataFixture, writeFakeView8 } from "./fakeView8.js";

const DISASSEMBLY = `Function: main
0x0000  LdaGlobal
0x0004  Star r0
`;

test("reports the cached-data header and bounded disassembly facts", async () => {
  const root = await createTestTempDirectory("rea-view8-");
  const { launcher, callsPath } = await writeFakeView8(root, {
    disassembly: DISASSEMBLY,
  });
  const provider = new View8Provider({
    environment: { REA_VIEW8_COMMAND: launcher },
  });
  const target = join(root, "main.jsc");
  await writeFile(target, cachedDataFixture(Buffer.from("payload-bytes")));
  const result = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: target },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.client).toEqual({ command: launcher, version: null });
  expect(value.container).toMatchObject({
    state: "recognized",
    magic: "v8-cached-data",
    magic_hex: "c0de0000",
    version_hash: 0x1234_5678,
    source_hash: 0x8765_4321,
    flag_hash: 1,
    snapshot_checksum: 0xdead_beef,
    declared_payload_bytes: 13,
    observed_payload_bytes: 13,
    payload_length_matches: true,
  });
  expect(value.disassembly).toMatchObject({
    bytes: DISASSEMBLY.length,
    empty: false,
  });
  expect(value.coverage).toBe("complete");
  expect(JSON.stringify(result.value)).not.toContain("LdaGlobal");
  await provider.close();
  expect(await readFile(callsPath, "utf8")).toContain(`["${target}"]`);
});

test("reports an unrecognized container without repairing it", async () => {
  const root = await createTestTempDirectory("rea-view8-plain-");
  const { launcher } = await writeFakeView8(root, {
    disassembly: "not bytecode\n",
  });
  const provider = new View8Provider({
    environment: { REA_VIEW8_COMMAND: launcher },
  });
  const target = join(root, "plain.jsc");
  await writeFile(target, "console.log('not bytecode')\n");
  const result = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: target },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.container).toMatchObject({
    state: "unrecognized",
    magic: "unknown",
    version_hash: null,
    declared_payload_bytes: null,
    payload_length_matches: null,
  });
  expect(value.coverage).toBe("partial");
  await provider.close();
});

test("reports a declared payload length that disagrees with the file", async () => {
  const root = await createTestTempDirectory("rea-view8-truncated-");
  const { launcher } = await writeFakeView8(root, {
    disassembly: "0x0000 Nop\n",
  });
  const provider = new View8Provider({
    environment: { REA_VIEW8_COMMAND: launcher },
  });
  const target = join(root, "truncated.jsc");
  await writeFile(
    target,
    cachedDataFixture(Buffer.from("short"), { declaredLength: 4096 }),
  );
  const result = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: target },
  });
  if (!result.ok) throw result.error;
  expect(result.value.result).toMatchObject({
    container: { payload_length_matches: false, declared_payload_bytes: 4096 },
  });
  await provider.close();
});

test("refuses plainly when no launcher is selected", async () => {
  const provider = new View8Provider({ environment: {} });
  const result = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: "/does/not/matter.jsc" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_VIEW8_COMMAND");
  await provider.close();
});

test("refuses a relative launcher path before reading the artifact", async () => {
  const provider = new View8Provider({
    environment: { REA_VIEW8_COMMAND: "view8" },
  });
  const result = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: "/does/not/matter.jsc" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.message).toContain("absolute path");
  await provider.close();
});

test("rejects an empty disassembly instead of reporting success", async () => {
  const root = await createTestTempDirectory("rea-view8-empty-");
  const { launcher } = await writeFakeView8(root, { disassembly: "" });
  const provider = new View8Provider({
    environment: { REA_VIEW8_COMMAND: launcher },
  });
  const target = join(root, "main.jsc");
  await writeFile(target, cachedDataFixture(Buffer.from("payload")));
  const result = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: target },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("surfaces a launcher failure without leaking its disassembly", async () => {
  const root = await createTestTempDirectory("rea-view8-fail-");
  const { launcher } = await writeFakeView8(root, {
    disassembly: "secret-opcode-dump",
    stderr: "patched V8 revision mismatch",
    exitCode: 3,
  });
  const provider = new View8Provider({
    environment: { REA_VIEW8_COMMAND: launcher },
  });
  const target = join(root, "main.jsc");
  await writeFile(target, cachedDataFixture(Buffer.from("payload")));
  const result = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: target },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("ProviderAdapterError");
  expect(projectAnalysisError(result.error).message).toContain(
    "patched V8 revision mismatch",
  );
  await provider.close();
});

test("probes the selected launcher without reading bytecode", async () => {
  const root = await createTestTempDirectory("rea-view8-avail-");
  const { launcher, callsPath } = await writeFakeView8(root, {});
  const provider = new View8Provider({
    environment: { REA_VIEW8_COMMAND: launcher },
  });
  expect(await provider.inspectAvailability()).toMatchObject({
    status: "available",
    diagnostics: { selected_command: launcher, version_probed: false },
  });
  expect(await readFile(callsPath, "utf8")).toBe("");
  await provider.close();

  const unconfigured = new View8Provider({ environment: {} });
  expect(await unconfigured.inspectAvailability()).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await unconfigured.close();
});
