import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { View8Provider } from "../../../../src/javascript/v8/View8Provider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  documentedCachedDataFixture,
  realCachedData,
  writeFakeView8,
} from "./fakeView8.js";

const DISASSEMBLY = `Function: main
0x0000  LdaGlobal
0x0004  Star r0
`;
const SOURCE = "function main(){ return 1; }";

const execute = async (environment: Record<string, string>, path: string) => {
  const provider = new View8Provider({ environment });
  const result = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path },
  });
  await provider.close();
  return result;
};

test("decodes a real cached-data header at the pinned offsets", async () => {
  const root = await createTestTempDirectory("rea-view8-");
  const { launcher, callsPath } = await writeFakeView8(root, {
    disassembly: DISASSEMBLY,
  });
  const target = join(root, "main.jsc");
  const real = realCachedData(SOURCE);
  await writeFile(target, real);
  const result = await execute({ REA_VIEW8_COMMAND: launcher }, target);
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.client).toEqual({ command: launcher, version: null });
  // Every expected word is read from the artifact V8 produced, not from the
  // decode's own constants.
  expect(value.container).toMatchObject({
    state: "recognized",
    layout: "v8-code-cache-32-byte-header",
    magic: "v8-cached-data",
    magic_hex: real.readUInt32LE(0).toString(16).padStart(8, "0"),
    header_bytes: 32,
    version_hash: real.readUInt32LE(4),
    source_length: SOURCE.length,
    flag_hash: real.readUInt32LE(12),
    snapshot_checksum: real.readUInt32LE(16),
    source_hash: null,
    payload_checksum: null,
    declared_payload_bytes: real.byteLength - 32,
    observed_payload_bytes: real.byteLength - 32,
  });
  expect(value.container).toMatchObject({
    prefix_words: Array.from({ length: 8 }, (_, index) =>
      real.readUInt32LE(index * 4),
    ),
  });
  expect(value.disassembly).toMatchObject({
    bytes: DISASSEMBLY.length,
    empty: false,
  });
  expect(value.coverage).toBe("complete");
  expect(JSON.stringify(result.value)).not.toContain("LdaGlobal");
  expect(await readFile(callsPath, "utf8")).toContain(`["${target}"]`);
});

test("tracks the source length V8 writes for a longer source", async () => {
  const root = await createTestTempDirectory("rea-view8-length-");
  const { launcher } = await writeFakeView8(root, {
    disassembly: "0x0000 Nop\n",
  });
  const provider = new View8Provider({
    environment: { REA_VIEW8_COMMAND: launcher },
  });
  const short = join(root, "short.jsc");
  const long = join(root, "long.jsc");
  const longSource = `${SOURCE}\n${"// padding\n".repeat(40)}`;
  await writeFile(short, realCachedData(SOURCE));
  await writeFile(long, realCachedData(longSource));
  const shortResult = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: short },
  });
  const longResult = await provider.execute({
    operation: "decompile_v8_bytecode",
    input: { path: long },
  });
  await provider.close();
  if (!shortResult.ok) throw shortResult.error;
  if (!longResult.ok) throw longResult.error;
  const shortContainer = (shortResult.value.result as Record<string, unknown>)
    .container as Record<string, unknown>;
  const longContainer = (longResult.value.result as Record<string, unknown>)
    .container as Record<string, unknown>;
  expect(shortContainer.source_length).toBe(SOURCE.length);
  expect(longContainer.source_length).toBe(longSource.length);
  expect(shortContainer.version_hash).toBe(longContainer.version_hash);
  expect(shortContainer.flag_hash).toBe(longContainer.flag_hash);
});

test("keeps header words uninterpreted when no pinned layout fits", async () => {
  const root = await createTestTempDirectory("rea-view8-truncated-");
  const { launcher } = await writeFakeView8(root, {
    disassembly: "0x0000 Nop\n",
  });
  const real = realCachedData(SOURCE);
  const truncated = real.subarray(0, real.byteLength - 8);
  const target = join(root, "truncated.jsc");
  await writeFile(target, truncated);
  const result = await execute({ REA_VIEW8_COMMAND: launcher }, target);
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const container = (result.value.result as Record<string, unknown>)
    .container as Record<string, unknown>;
  expect(container).toMatchObject({
    state: "layout_unverifiable",
    layout: null,
    magic: "v8-cached-data",
    header_bytes: null,
    version_hash: null,
    source_length: null,
    declared_payload_bytes: null,
    observed_payload_bytes: null,
  });
  expect(container.prefix_words).toEqual(
    Array.from({ length: 8 }, (_, index) => truncated.readUInt32LE(index * 4)),
  );
  expect((result.value.result as Record<string, unknown>).coverage).toBe(
    "partial",
  );
  expect(result.value.limitations.join("\n")).toContain(
    "no pinned header layout declares its observed payload size",
  );
});

test("decodes the documented bytenode-era layout with its own word map", async () => {
  const root = await createTestTempDirectory("rea-view8-documented-");
  const { launcher } = await writeFakeView8(root, {
    disassembly: "0x0000 Nop\n",
  });
  const target = join(root, "legacy.jsc");
  await writeFile(target, documentedCachedDataFixture(Buffer.from("payload")));
  const result = await execute({ REA_VIEW8_COMMAND: launcher }, target);
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(
    (result.value.result as Record<string, unknown>).container,
  ).toMatchObject({
    state: "recognized",
    layout: "v8-code-cache-24-byte-header",
    header_bytes: 24,
    source_hash: 0x5566_7788,
    source_length: null,
    payload_checksum: 0xdead_beef,
    snapshot_checksum: null,
    declared_payload_bytes: 7,
    observed_payload_bytes: 7,
  });
});

test("reports an unrecognized container without repairing it", async () => {
  const root = await createTestTempDirectory("rea-view8-plain-");
  const { launcher } = await writeFakeView8(root, {
    disassembly: "not bytecode\n",
  });
  const target = join(root, "plain.jsc");
  await writeFile(target, "console.log('not bytecode')\n");
  const result = await execute({ REA_VIEW8_COMMAND: launcher }, target);
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.container).toMatchObject({
    state: "unrecognized",
    layout: null,
    magic: "unknown",
    version_hash: null,
    declared_payload_bytes: null,
    observed_payload_bytes: null,
  });
  expect(value.coverage).toBe("partial");
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
  const target = join(root, "main.jsc");
  await writeFile(target, realCachedData(SOURCE));
  const result = await execute({ REA_VIEW8_COMMAND: launcher }, target);
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
});

test("surfaces the launcher failure without republishing its disassembly", async () => {
  const root = await createTestTempDirectory("rea-view8-fail-");
  const { launcher } = await writeFakeView8(root, {
    disassembly: "secret-opcode-dump",
    stderr: "patched V8 revision mismatch",
    exitCode: 3,
  });
  const target = join(root, "main.jsc");
  await writeFile(target, realCachedData(SOURCE));
  const result = await execute({ REA_VIEW8_COMMAND: launcher }, target);
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("ProviderAdapterError");
  const projected = projectAnalysisError(result.error);
  expect(projected.message).toContain("patched V8 revision mismatch");
  expect(JSON.stringify(projected)).not.toContain("secret-opcode-dump");
  expect(JSON.stringify(result.error)).not.toContain("secret-opcode-dump");
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
