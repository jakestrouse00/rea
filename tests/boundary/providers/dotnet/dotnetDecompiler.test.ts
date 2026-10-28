import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { DotnetDecompilerProvider } from "../../../../src/manageddecomp/DotnetDecompilerProvider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { writeFakeIlspy } from "./fakeIlspy.js";

const SOURCE = `namespace Example.App
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("hello");
        }

        public int Count { get; set; }

        private string name;

        public Program()
        {
            name = "x";
        }
    }

    internal enum Mode
    {
        A,
        B
    }
}
`;

const providerFor = async (
  source: string,
): Promise<{
  readonly provider: DotnetDecompilerProvider;
  readonly callsPath: string;
  readonly root: string;
}> => {
  const root = await createTestTempDirectory("rea-dotnet-");
  const { launcher, callsPath } = await writeFakeIlspy(root, { source });
  return {
    provider: new DotnetDecompilerProvider({
      environment: { REA_ILSPY_CMD_PATH: launcher },
    }),
    callsPath,
    root,
  };
};

test("reports type and member declarations without leaking C# text", async () => {
  const { provider, callsPath, root } = await providerFor(SOURCE);
  const target = join(root, "App.dll");
  await writeFile(target, "MZ-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_dotnet_assembly",
    input: { path: target },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.client).toEqual({
    command: expect.any(String),
    version: "8.2.0.7535",
  });
  expect(value.assembly_name).toBe("App");
  expect(value.type_count).toBe(2);
  expect(value.types).toEqual([
    {
      namespace: "Example.App",
      name: "Program",
      kind: "class",
      base_type: null,
      members: [
        {
          kind: "method",
          name: "Main",
          signature: "public static void Main(string[] args)",
        },
        {
          kind: "property",
          name: "Count",
          signature: "public int Count",
        },
        { kind: "field", name: "name", signature: "private string name" },
        {
          kind: "constructor",
          name: "Program",
          signature: "public Program()",
        },
      ],
    },
    {
      namespace: "Example.App",
      name: "Mode",
      kind: "enum",
      base_type: null,
      members: [
        { kind: "field", name: "A", signature: "A" },
        { kind: "field", name: "B", signature: "B" },
      ],
    },
  ]);
  expect(JSON.stringify(result.value)).not.toContain("Console.WriteLine");
  expect(JSON.stringify(result.value)).not.toContain("hello");
  await provider.close();
  expect(await readFile(callsPath, "utf8")).toContain(`["${target}"]`);
});

test("refuses plainly when REA_ILSPY_CMD_PATH is unset", async () => {
  const provider = new DotnetDecompilerProvider({ environment: {} });
  const result = await provider.execute({
    operation: "decompile_dotnet_assembly",
    input: { path: "/does/not/matter.dll" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_ILSPY_CMD_PATH");
  await provider.close();
});

test("rejects output without declarations", async () => {
  const { provider, root } = await providerFor("not C# at all\n");
  const target = join(root, "App.dll");
  await writeFile(target, "MZ-FIXTURE");
  const result = await provider.execute({
    operation: "decompile_dotnet_assembly",
    input: { path: target },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("probes the selected ilspycmd before reporting availability", async () => {
  const { provider } = await providerFor(SOURCE);
  const available = await provider.inspectAvailability();
  expect(available.status, JSON.stringify(available)).toBe("available");
  expect(available.diagnostics).toMatchObject({ version: "8.2.0.7535" });
  await provider.close();

  const unconfigured = new DotnetDecompilerProvider({ environment: {} });
  expect(await unconfigured.inspectAvailability()).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await unconfigured.close();
});
