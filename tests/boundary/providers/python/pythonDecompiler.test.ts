import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { PythonDecompilerProvider } from "../../../../src/pysrc/PythonDecompilerProvider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { writeFakePythonDecompiler } from "./fakePythonDecompiler.js";

const SOURCE = `import os, sys
from collections import OrderedDict

class Greeter:
    def __init__(self, name):
        self.name = name

    def greet(self, loud=False):
        return self.name

def main(argv):
    return 0
`;

test("recovers declarations, line ranges, and import module names", async () => {
  const root = await createTestTempDirectory("rea-python-");
  const { launcher, callsPath } = await writeFakePythonDecompiler(
    root,
    "pycdc",
    { source: SOURCE },
  );
  const provider = new PythonDecompilerProvider({
    environment: { REA_PYCDC_COMMAND: launcher },
  });
  const target = join(root, "module.pyc");
  await writeFile(target, "PYC-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_python_bytecode",
    input: { path: target },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.client).toEqual({ command: launcher, version: null });
  expect(value.functions).toEqual([
    {
      name: "__init__",
      qualified_name: "Greeter.__init__",
      line_start: 5,
      line_end: 6,
      parameter_count: 1,
    },
    {
      name: "greet",
      qualified_name: "Greeter.greet",
      line_start: 8,
      line_end: 9,
      parameter_count: 1,
    },
    {
      name: "main",
      qualified_name: "main",
      line_start: 11,
      line_end: 12,
      parameter_count: 1,
    },
  ]);
  expect(value.classes).toEqual(["Greeter"]);
  expect(value.imports).toEqual(["os", "sys", "collections"]);
  expect(value.function_count).toBe(3);
  expect(JSON.stringify(result.value)).not.toContain("self.name");
  await provider.close();
  expect(await readFile(callsPath, "utf8")).toContain(`["${target}"]`);
});

test("prefers PyLingual when both settings are present", async () => {
  const root = await createTestTempDirectory("rea-python-pref-");
  const { launcher: pylingual, callsPath: pylingualCalls } =
    await writeFakePythonDecompiler(root, "pylingual", { source: SOURCE });
  const { callsPath: pycdcCalls } = await writeFakePythonDecompiler(
    root,
    "pycdc",
    { source: SOURCE },
  );
  const provider = new PythonDecompilerProvider({
    environment: {
      REA_PYLINGUAL_COMMAND: pylingual,
      REA_PYCDC_COMMAND: join(root, "pycdc"),
    },
  });
  const target = join(root, "module.pyc");
  await writeFile(target, "PYC-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_python_bytecode",
    input: { path: target },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect((result.value.result as Record<string, unknown>).client).toEqual({
    command: pylingual,
    version: null,
  });
  await provider.close();
  expect(await readFile(pylingualCalls, "utf8")).toContain(`["${target}"]`);
  expect(await readFile(pycdcCalls, "utf8")).toBe("");
});

test("refuses plainly when neither decompiler is selected", async () => {
  const provider = new PythonDecompilerProvider({ environment: {} });
  const result = await provider.execute({
    operation: "decompile_python_bytecode",
    input: { path: "/does/not/matter.pyc" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_PYLINGUAL_COMMAND");
  expect(result.error.message).toContain("REA_PYCDC_COMMAND");
  await provider.close();
});

test("rejects output without declarations", async () => {
  const root = await createTestTempDirectory("rea-python-empty-");
  const { launcher } = await writeFakePythonDecompiler(root, "pycdc", {
    source: "# just a comment\n",
  });
  const provider = new PythonDecompilerProvider({
    environment: { REA_PYCDC_COMMAND: launcher },
  });
  const target = join(root, "module.pyc");
  await writeFile(target, "PYC-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_python_bytecode",
    input: { path: target },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("probes the selected decompiler without reading bytecode", async () => {
  const root = await createTestTempDirectory("rea-python-avail-");
  const { launcher } = await writeFakePythonDecompiler(root, "pycdc", {
    source: SOURCE,
  });
  const provider = new PythonDecompilerProvider({
    environment: { REA_PYCDC_COMMAND: launcher },
  });
  expect(await provider.inspectAvailability()).toMatchObject({
    status: "available",
    diagnostics: { selected_tool: "pycdc", version_probed: false },
  });
  await provider.close();

  const unconfigured = new PythonDecompilerProvider({ environment: {} });
  expect(await unconfigured.inspectAvailability()).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await unconfigured.close();
});
