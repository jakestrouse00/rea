import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { SymbolRecoveryProvider } from "../../../../src/symbolrecovery/SymbolRecoveryProvider.js";
import { parseDemangledNames } from "../../../../src/symbolrecovery/SymbolRecoveryOutput.js";
import { writeFakeSymbolTool } from "./fakeSymbolTool.js";

const GO_FIXTURE = JSON.stringify({
  Version: "go1.22.1",
  Arch: "amd64",
  OS: "linux",
  ModuleInfo: { Path: "example.com/app" },
  UserFunctions: [
    { Start: 4_198_400, End: 4_198_464, FullName: "main.main" },
    { Start: 4_198_464, End: 4_198_500, FullName: "main.run" },
    { unexpected: true },
  ],
});

const BREAKPAD_FIXTURE = [
  "MODULE Linux x86_64 A1B2C3D4E5F6 libnative.so",
  "FILE 0 /src/a.c",
  "FUNC 1000 20 0 main",
  "FUNC m 1020 10 8 helper",
  "PUBLIC 1100 0 exported",
  "",
].join("\n");

const providerFor = async (root: string): Promise<SymbolRecoveryProvider> =>
  new SymbolRecoveryProvider({ environment: { PATH: "/nonexistent" } });

test("pairs demangler output with its input and treats an echo as unchanged", () => {
  expect(
    parseDemangledNames(
      ["_RNv3bar", "_RNv3foo", "_RNv3baz"],
      "_RNv3bar\nmycrate::foo\n\n",
    ),
  ).toEqual([
    { mangled: "_RNv3bar", demangled: null },
    { mangled: "_RNv3foo", demangled: "mycrate::foo" },
    { mangled: "_RNv3baz", demangled: null },
  ]);
});

test("recovers Go functions, entries, sizes, and module identity", async () => {
  const root = await createTestTempDirectory("rea-symbols-go-");
  const { launcher, callsPath } = await writeFakeSymbolTool(root, "GoReSym", {
    stdout: GO_FIXTURE,
  });
  const provider = new SymbolRecoveryProvider({
    environment: { REA_GORESYM_COMMAND: launcher },
  });
  const target = join(root, "server");
  await writeFile(target, "GO-FIXTURE");
  const result = await provider.execute({
    operation: "recover_go_symbols",
    input: { path: target },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.go_version).toBe("go1.22.1");
  expect(value.arch).toBe("amd64");
  expect(value.os).toBe("linux");
  expect(value.module_path).toBe("example.com/app");
  expect(value.sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(value.function_count).toBe(2);
  expect(value.unparsed_entries).toBe(1);
  expect(value.coverage).toBe("partial");
  expect(value.functions).toEqual([
    { name: "main.main", entry: "0x401000", size: 64 },
    { name: "main.run", entry: "0x401040", size: 36 },
  ]);
  await provider.close();
  expect(await readFile(callsPath, "utf8")).toContain(`["${target}"]`);
});

test("demangles Rust names and reports unchanged lines as null", async () => {
  const root = await createTestTempDirectory("rea-symbols-rust-");
  const { launcher, callsPath } = await writeFakeSymbolTool(root, "rustfilt", {
    stdout: "mycrate::foo\n\n",
  });
  const provider = new SymbolRecoveryProvider({
    environment: { REA_RUSTFILT_COMMAND: launcher },
  });
  const result = await provider.execute({
    operation: "demangle_rust_name",
    input: { names: ["_RNv3foo", "_RNv3bar"] },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.names).toEqual([
    { mangled: "_RNv3foo", demangled: "mycrate::foo" },
    { mangled: "_RNv3bar", demangled: null },
  ]);
  expect(value.demangled_count).toBe(1);
  expect(value.coverage).toBe("partial");
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain('["_RNv3foo","_RNv3bar"]');
});

test("reports an echoed mangled name as null rather than a demangle", async () => {
  const root = await createTestTempDirectory("rea-symbols-echo-");
  const { launcher } = await writeFakeSymbolTool(root, "rustfilt", {
    stdout: "_RNv3bar\nmycrate::foo\n",
  });
  const provider = new SymbolRecoveryProvider({
    environment: { REA_RUSTFILT_COMMAND: launcher },
  });
  const result = await provider.execute({
    operation: "demangle_rust_name",
    input: { names: ["_RNv3bar", "_RNv3foo"] },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.names).toEqual([
    { mangled: "_RNv3bar", demangled: null },
    { mangled: "_RNv3foo", demangled: "mycrate::foo" },
  ]);
  expect(value.demangled_count).toBe(1);
  expect(value.coverage).toBe("partial");
  await provider.close();
});

test("resolves rustfilt from PATH when no setting is selected", async () => {
  const root = await createTestTempDirectory("rea-symbols-path-");
  const { launcher } = await writeFakeSymbolTool(root, "rustfilt", {
    stdout: "mycrate::foo\n",
  });
  const provider = new SymbolRecoveryProvider({
    environment: { PATH: root },
  });
  const result = await provider.execute({
    operation: "demangle_rust_name",
    input: { names: ["_RNv3foo"] },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect((result.value.result as Record<string, unknown>).client).toEqual({
    command: launcher,
    version: null,
  });
  await provider.close();
});

test("parses a Breakpad symbol table and keeps the text out of Evidence", async () => {
  const root = await createTestTempDirectory("rea-symbols-breakpad-");
  const { launcher } = await writeFakeSymbolTool(root, "dump_syms", {
    stdout: BREAKPAD_FIXTURE,
  });
  const provider = new SymbolRecoveryProvider({
    environment: { REA_DUMP_SYMS_COMMAND: launcher },
  });
  const target = join(root, "libnative.so");
  await writeFile(target, "ELF-FIXTURE");
  const result = await provider.execute({
    operation: "generate_symbol_table",
    input: { path: target },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.module).toEqual({
    os: "Linux",
    arch: "x86_64",
    id: "A1B2C3D4E5F6",
    name: "libnative.so",
  });
  expect(value.function_count).toBe(2);
  expect(value.public_count).toBe(1);
  expect(value.file_count).toBe(1);
  expect(value.functions).toEqual([
    {
      name: "main",
      address: "1000",
      size: 32,
      parameter_size: 0,
    },
    {
      name: "helper",
      address: "1020",
      size: 16,
      parameter_size: 8,
    },
  ]);
  expect(JSON.stringify(result.value)).not.toContain("/src/a.c");
  await provider.close();
});

test("refuses each tool plainly when its executable is not selected", async () => {
  const provider = await providerFor("");
  for (const [operation, input, setting] of [
    ["recover_go_symbols", { path: "/does/not/matter" }, "REA_GORESYM_COMMAND"],
    ["demangle_rust_name", { names: ["_RNv3foo"] }, "REA_RUSTFILT_COMMAND"],
    [
      "generate_symbol_table",
      { path: "/does/not/matter" },
      "REA_DUMP_SYMS_COMMAND",
    ],
  ] as const) {
    const result = await provider.execute({ operation, input } as never);
    expect(result.ok).toBe(false);
    if (result.ok) continue;
    expect(projectAnalysisError(result.error).code).toBe(
      "capability_unavailable",
    );
    expect(result.error.message).toContain(setting);
  }
  await provider.close();
});

test("reports each tool separately in the availability probe", async () => {
  const root = await createTestTempDirectory("rea-symbols-availability-");
  const { launcher } = await writeFakeSymbolTool(root, "GoReSym", {
    stdout: GO_FIXTURE,
  });
  const provider = new SymbolRecoveryProvider({
    environment: { REA_GORESYM_COMMAND: launcher, PATH: "/nonexistent" },
  });
  expect(provider.inspectToolAvailability("recover_go_symbols")).toMatchObject({
    status: "available",
  });
  expect(provider.inspectToolAvailability("demangle_rust_name")).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  expect(
    provider.inspectToolAvailability("generate_symbol_table"),
  ).toMatchObject({ status: "unavailable", code: "not_configured" });
  const aggregate = await provider.inspectAvailability();
  expect(aggregate.status).toBe("available");
  expect(aggregate.diagnostics).toEqual({
    recover_go_symbols: true,
    demangle_rust_name: false,
    generate_symbol_table: false,
  });
  await provider.close();
});

test("rejects GoReSym output that is not a symbol document", async () => {
  const root = await createTestTempDirectory("rea-symbols-bad-");
  const { launcher } = await writeFakeSymbolTool(root, "GoReSym", {
    stdout: "null\n",
  });
  const provider = new SymbolRecoveryProvider({
    environment: { REA_GORESYM_COMMAND: launcher },
  });
  const target = join(root, "server");
  await writeFile(target, "GO-FIXTURE");
  const result = await provider.execute({
    operation: "recover_go_symbols",
    input: { path: target },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});
