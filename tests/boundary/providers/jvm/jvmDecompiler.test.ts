import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { JvmDecompilerProvider } from "../../../../src/jvmdecomp/JvmDecompilerProvider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { writeFakeJava, type FakeJavaBehavior } from "./fakeJava.js";

const MAIN_SOURCE = `package com.example;

public class Main {
    private int count;

    public Main(int count) {
        this.count = count;
    }

    public int count() {
        return count;
    }
}
`;

const HELPER_SOURCE = `package com.example;

interface Helper {
    void help(String text);
}
`;

const providerFor = async (
  behavior: FakeJavaBehavior,
): Promise<{
  readonly provider: JvmDecompilerProvider;
  readonly callsPath: string;
  readonly root: string;
  readonly jarPath: string;
}> => {
  const root = await createTestTempDirectory("rea-jvm-");
  const { callsPath } = await writeFakeJava(root, behavior);
  const jarPath = join(root, "vineflower.jar");
  await writeFile(jarPath, "JAR-FIXTURE");
  return {
    provider: new JvmDecompilerProvider({
      environment: { REA_VINEFLOWER_JAR: jarPath, PATH: root },
    }),
    callsPath,
    root,
    jarPath,
  };
};

test("decompiles one selected class and reports declarations", async () => {
  const { provider, callsPath, root, jarPath } = await providerFor({
    files: { "com/example/Main.java": MAIN_SOURCE },
  });
  const container = join(root, "app.jar");
  await writeFile(container, "ZIP-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_jar_class",
    input: { path: container, class_name: "com/example/Main" },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.decompiler_jar).toBe(jarPath);
  expect(value.java).toEqual({
    command: expect.any(String),
    version: expect.stringContaining("17.0.1"),
  });
  expect(value.class_count).toBe(1);
  expect(value.classes).toEqual([
    {
      binary_name: "com.example.Main",
      package: "com.example",
      name: "Main",
      kind: "class",
      members: [
        { kind: "field", name: "count", signature: "private int count" },
        {
          kind: "constructor",
          name: "Main",
          signature: "public Main(int count)",
        },
        {
          kind: "method",
          name: "count",
          signature: "public int count()",
        },
      ],
    },
  ]);
  expect(JSON.stringify(result.value)).not.toContain("this.count = count");
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain(`"-only=com.example.Main","${container}"`);
});

test("decompiles an archive and marks a class-bounded result partial", async () => {
  const { provider, root } = await providerFor({
    files: {
      "com/example/Main.java": MAIN_SOURCE,
      "com/example/Helper.java": HELPER_SOURCE,
    },
  });
  const container = join(root, "app.jar");
  await writeFile(container, "ZIP-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_jar_archive",
    input: { path: container, max_classes: 1 },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.class_count).toBe(1);
  expect(value.truncated).toBe(true);
  expect(value.coverage).toBe("partial");
  await provider.close();
});

test("refuses plainly when no Vineflower JAR is selected", async () => {
  const provider = new JvmDecompilerProvider({ environment: {} });
  const result = await provider.execute({
    operation: "decompile_jar_archive",
    input: { path: "/does/not/matter.jar" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_VINEFLOWER_JAR");
  await provider.close();
});

test("refuses a Java runtime older than 11", async () => {
  const { provider, root } = await providerFor({
    version: 'openjdk version "1.8.0_392"\n',
  });
  const container = join(root, "app.jar");
  await writeFile(container, "ZIP-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_jar_archive",
    input: { path: container },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("Java");
  await provider.close();

  const available = await provider.inspectAvailability();
  expect(available).toMatchObject({
    status: "unavailable",
    code: "unsupported_version",
  });
});

test("reports availability after probing the JAR and JDK", async () => {
  const { provider } = await providerFor({});
  const available = await provider.inspectAvailability();
  expect(available.status).toBe("available");
  expect(available.diagnostics).toMatchObject({ java_major: 17 });
  await provider.close();
});

const failingRootFactory = async (path: string) => ({
  path,
  close: async () => {
    throw new Error("root removal denied");
  },
});

test("retains a successful decompilation when root cleanup fails", async () => {
  const root = await createTestTempDirectory("rea-jvm-cleanup-");
  const { launcher } = await writeFakeJava(root, {
    files: { "com/example/Main.java": MAIN_SOURCE },
  });
  const jarPath = join(root, "vineflower.jar");
  await writeFile(jarPath, "JAR-FIXTURE");
  const runtimeRoot = await createTestTempDirectory("rea-jvm-root-");
  const provider = new JvmDecompilerProvider({
    environment: { REA_VINEFLOWER_JAR: jarPath, PATH: root },
    createRuntimeRoot: async () => failingRootFactory(runtimeRoot),
  });
  const container = join(root, "app.jar");
  await writeFile(container, "ZIP-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_jar_class",
    input: { path: container, class_name: "com/example/Main" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.cleanupIncomplete).toBe(true);
  expect(result.error.partialObservation).toMatchObject({
    kind: "provider-result",
    operation: "decompile_jar_class",
  });
  const partial = result.error.partialObservation as
    | { kind: "provider-result"; result: unknown }
    | undefined;
  if (partial?.kind !== "provider-result") return;
  expect(partial.result).toMatchObject({ class_count: 1 });
  expect(result.error.cleanupResources).toContain(runtimeRoot);
  expect(result.error.cleanup?.reason).toContain("root removal denied");
  await provider.close();
});

test("preserves the real decompilation error when root cleanup also fails", async () => {
  const root = await createTestTempDirectory("rea-jvm-cleanup-fail-");
  const { launcher } = await writeFakeJava(root, { exit: 3 });
  const jarPath = join(root, "vineflower.jar");
  await writeFile(jarPath, "JAR-FIXTURE");
  const runtimeRoot = await createTestTempDirectory("rea-jvm-root-fail-");
  const provider = new JvmDecompilerProvider({
    environment: { REA_VINEFLOWER_JAR: jarPath, PATH: root },
    createRuntimeRoot: async () => failingRootFactory(runtimeRoot),
  });
  const container = join(root, "app.jar");
  await writeFile(container, "ZIP-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_jar_archive",
    input: { path: container },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.cleanupIncomplete).toBe(true);
  expect(result.error.cleanupPrimary?._tag).toBe("ProviderAdapterError");
  expect(JSON.stringify(result.error.diagnostics?.primary_error)).toContain(
    "Vineflower failed",
  );
  expect(JSON.stringify(result.error.diagnostics?.cleanup_error)).toContain(
    "root removal denied",
  );
  await provider.close();
});
