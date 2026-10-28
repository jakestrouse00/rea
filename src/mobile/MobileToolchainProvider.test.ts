import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { MobileToolchainProvider } from "./MobileToolchainProvider.js";
import {
  ANDROGUARD_PYTHON_ENV,
  ILEAPP_COMMAND_ENV,
  OBJECTION_COMMAND_ENV,
} from "./MobileToolchainRelease.js";
import type {
  MobileCommandRun,
  MobileCommandRunner,
} from "./MobileToolchainConfiguration.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  for (const directory of temporaryDirectories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

interface ScriptedRun {
  readonly command: string;
  readonly arguments: readonly string[];
}

const fakeRunner = (
  respond: (run: ScriptedRun) => MobileCommandRun,
): { readonly run: MobileCommandRunner; readonly calls: ScriptedRun[] } => {
  const calls: ScriptedRun[] = [];
  return {
    calls,
    run: async (request) => {
      const scripted = {
        command: request.command,
        arguments: [...request.arguments],
      };
      calls.push(scripted);
      return respond(scripted);
    },
  };
};

const apkFixture = async (): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-mobile-test-"));
  temporaryDirectories.push(directory);
  const path = join(directory, "app.apk");
  await writeFile(path, "APK-fake-bytes", "utf8");
  return path;
};

const completed = (stdout: string): MobileCommandRun => ({
  stdout,
  stderr: "",
  exit_code: 0,
  timed_out: false,
  output_truncated: false,
});

const androguardStructureDocument = {
  schema: "rea.androguard.v1",
  operation: "structure",
  androguard_version: "5.0.0",
  package: "com.example.app",
  app_name: "Example",
  version_name: "1.2.3",
  version_code: "42",
  min_sdk: 24,
  target_sdk: 33,
  permissions: ["android.permission.INTERNET"],
  components: [
    { kind: "activity", name: "com.example.app.Main", exported: true },
    { kind: "service", name: "com.example.app.Sync", exported: false },
  ],
  component_count: 2,
  components_truncated: false,
  cross_references: [
    { from: "com.example.app.Main", to: "com.example.lib.Client", count: 3 },
  ],
  cross_reference_count: 1,
  cross_references_truncated: false,
  native_libraries: ["libnative.so"],
  unparsed_facts: 0,
  warnings: [],
};

describe("mobile toolchain configuration refusals", () => {
  it("refuses every lane when its selection is unset", async () => {
    const provider = new MobileToolchainProvider({
      environment: {},
      run: fakeRunner(() => completed("")).run,
    });
    const apk = await apkFixture();
    const objection = await provider.execute({
      operation: "run_objection_recipe",
      input: {
        recipe: "list-loaded-classes",
        target_kind: "bundle",
        target: "com.example.app",
        max_rows: 200,
        timeout_ms: 60_000,
      },
    });
    expect(objection.ok).toBe(false);
    const androguard = await provider.execute({
      operation: "analyze_apk_structure",
      input: {
        apk_path: apk,
        max_components: 500,
        max_cross_references: 500,
      },
    });
    expect(androguard.ok).toBe(false);
    const forensics = await provider.execute({
      operation: "run_mobile_forensics_report",
      input: {
        input_path: apk,
        output_directory: "/tmp",
        platform: "ios",
        max_tables: 48,
        max_rows_per_table: 200,
        timeout_ms: 300_000,
      },
    });
    expect(forensics.ok).toBe(false);
    for (const refusal of [objection, androguard, forensics]) {
      if (refusal.ok) continue;
      expect(refusal.error.message).toContain("mobile-toolchain");
      expect(refusal.error.message).toContain("REA_");
    }
  });
});

describe("run_objection_recipe", () => {
  it("runs one whitelisted recipe and retains structure only", async () => {
    const scripted = fakeRunner(() =>
      completed(
        [
          "Using USB device `emulator-5554`",
          "com.example.net.NetClient",
          "com.example.net.NetClient",
          "com.example.db.Store",
        ].join("\n"),
      ),
    );
    const provider = new MobileToolchainProvider({
      environment: { [OBJECTION_COMMAND_ENV]: "/opt/rea/objection" },
      run: scripted.run,
    });
    const result = await provider.execute({
      operation: "run_objection_recipe",
      input: {
        recipe: "list-loaded-classes",
        target_kind: "bundle",
        target: "com.example.app",
        serial: "emulator-5554",
        max_rows: 200,
        timeout_ms: 60_000,
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(scripted.calls).toEqual([
      {
        command: "/opt/rea/objection",
        arguments: [
          "-g",
          "com.example.app",
          "-S",
          "emulator-5554",
          "run",
          "android",
          "hooking",
          "list",
          "classes",
        ],
      },
    ]);
    expect(result.value.result).toMatchObject({
      recipe: "list-loaded-classes",
      rows: ["com.example.net.NetClient", "com.example.db.Store"],
      row_count: 2,
      rows_truncated: false,
      dropped_line_count: 1,
      unparsed_line_count: 0,
      coverage: "complete",
    });
    const serialized = JSON.stringify(result.value);
    expect(serialized).not.toContain("Using USB device");
  });

  it("reports a non-zero exit as an adapter failure naming the recipe", async () => {
    const provider = new MobileToolchainProvider({
      environment: { [OBJECTION_COMMAND_ENV]: "/opt/rea/objection" },
      run: fakeRunner(() => ({
        stdout: "",
        stderr: "not attached",
        exit_code: 1,
        timed_out: false,
        output_truncated: false,
      })).run,
    });
    const result = await provider.execute({
      operation: "run_objection_recipe",
      input: {
        recipe: "list-activities",
        target_kind: "bundle",
        target: "com.example.app",
        max_rows: 200,
        timeout_ms: 60_000,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("ProviderAdapterError");
    expect(result.error.userMessage).toContain("list-activities");
  });

  it("refuses a recipe the whitelist does not carry", async () => {
    const provider = new MobileToolchainProvider({
      environment: { [OBJECTION_COMMAND_ENV]: "/opt/rea/objection" },
      run: fakeRunner(() => completed("")).run,
    });
    const result = await provider.execute({
      operation: "run_objection_recipe",
      input: {
        recipe: "free-form-shell" as "list-loaded-classes",
        target_kind: "bundle",
        target: "com.example.app",
        max_rows: 200,
        timeout_ms: 60_000,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });
});

describe("androguard structure and findings", () => {
  it("retains declared structure without executing the application", async () => {
    const apk = await apkFixture();
    const scripted = fakeRunner(() =>
      completed(JSON.stringify(androguardStructureDocument)),
    );
    const provider = new MobileToolchainProvider({
      environment: { [ANDROGUARD_PYTHON_ENV]: "/opt/rea/python3" },
      run: scripted.run,
    });
    const result = await provider.execute({
      operation: "analyze_apk_structure",
      input: {
        apk_path: apk,
        max_components: 500,
        max_cross_references: 500,
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(scripted.calls[0]!.command).toBe("/opt/rea/python3");
    expect(scripted.calls[0]!.arguments.slice(1, 3)).toEqual(["--apk", apk]);
    expect(scripted.calls[0]!.arguments[0]).toMatch(
      /bridge\/mobile\/androguard_bridge\.py$/u,
    );
    expect(result.value.result).toMatchObject({
      package: "com.example.app",
      min_sdk: 24,
      target_sdk: 33,
      permissions: ["android.permission.INTERNET"],
      components: [
        { kind: "activity", name: "com.example.app.Main", exported: true },
        { kind: "service", name: "com.example.app.Sync", exported: false },
      ],
      cross_references: [
        {
          from: "com.example.app.Main",
          to: "com.example.lib.Client",
          count: 3,
        },
      ],
      coverage: "complete",
    });
    expect(
      (result.value.result as { readonly apk: { readonly sha256: string } }).apk
        .sha256,
    ).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("bounds components and cross references to the caller's maxima", async () => {
    const apk = await apkFixture();
    const provider = new MobileToolchainProvider({
      environment: { [ANDROGUARD_PYTHON_ENV]: "/opt/rea/python3" },
      run: fakeRunner(() =>
        completed(JSON.stringify(androguardStructureDocument)),
      ).run,
    });
    const result = await provider.execute({
      operation: "analyze_apk_structure",
      input: {
        apk_path: apk,
        max_components: 1,
        max_cross_references: 1,
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const normalized = result.value.result as unknown as {
      readonly components: readonly unknown[];
      readonly components_truncated: boolean;
      readonly coverage: string;
    };
    expect(normalized.components).toHaveLength(1);
    expect(normalized.components_truncated).toBe(true);
    expect(normalized.coverage).toBe("partial");
  });

  it("keeps finding ids and locations only", async () => {
    const apk = await apkFixture();
    const provider = new MobileToolchainProvider({
      environment: { [ANDROGUARD_PYTHON_ENV]: "/opt/rea/python3" },
      run: fakeRunner(() =>
        completed(
          JSON.stringify({
            schema: "rea.androguard.v1",
            operation: "vulnerabilities",
            androguard_version: "5.0.0",
            findings: [
              {
                id: "exported-component-without-permission",
                severity: "warning",
                location: "activity:com.example.app.Main",
              },
            ],
            finding_count: 1,
            findings_truncated: false,
          }),
        ),
      ).run,
    });
    const result = await provider.execute({
      operation: "scan_apk_vulnerabilities",
      input: { apk_path: apk, max_findings: 200 },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.result).toMatchObject({
      findings: [
        {
          id: "exported-component-without-permission",
          severity: "warning",
          location: "activity:com.example.app.Main",
        },
      ],
      finding_count: 1,
      findings_truncated: false,
      coverage: "complete",
    });
  });

  it("refuses a bridge error document instead of reporting an empty inventory", async () => {
    const apk = await apkFixture();
    const provider = new MobileToolchainProvider({
      environment: { [ANDROGUARD_PYTHON_ENV]: "/opt/rea/python3" },
      run: fakeRunner(() =>
        completed(
          JSON.stringify({
            schema: "rea.androguard.v1",
            operation: "structure",
            error: "the APK could not be parsed: FileNotFoundError",
          }),
        ),
      ).run,
    });
    const result = await provider.execute({
      operation: "analyze_apk_structure",
      input: {
        apk_path: apk,
        max_components: 500,
        max_cross_references: 500,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisProtocolError");
  });
});

describe("run_mobile_forensics_report", () => {
  it("parses the tables the launcher wrote into the caller's directory", async () => {
    const apk = await apkFixture();
    const outputDirectory = await mkdtemp(join(tmpdir(), "rea-ileapp-out-"));
    temporaryDirectories.push(outputDirectory);
    const provider = new MobileToolchainProvider({
      environment: { [ILEAPP_COMMAND_ENV]: "/opt/rea/ileapp" },
      run: fakeRunner(() => {
        void writeFile(
          join(outputDirectory, "sms.tsv"),
          "id\tbody\n1\thello\n",
          "utf8",
        );
        return completed("");
      }).run,
    });
    // The scripted runner writes the table before the provider lists it.
    const scripted = fakeRunner(() => completed(""));
    const writingProvider = new MobileToolchainProvider({
      environment: { [ILEAPP_COMMAND_ENV]: "/opt/rea/ileapp" },
      run: async (request) => {
        await writeFile(
          join(outputDirectory, "sms.tsv"),
          "id\tbody\n1\thello\n",
          "utf8",
        );
        return scripted.run(request);
      },
    });
    void provider;
    const result = await writingProvider.execute({
      operation: "run_mobile_forensics_report",
      input: {
        input_path: apk,
        output_directory: outputDirectory,
        platform: "ios",
        max_tables: 48,
        max_rows_per_table: 200,
        timeout_ms: 300_000,
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(scripted.calls[0]!.arguments).toEqual([
      "-t",
      "ios",
      "-i",
      apk,
      "-o",
      outputDirectory,
    ]);
    expect(result.value.result).toMatchObject({
      table_count: 1,
      total_rows: 1,
      coverage: "complete",
    });
    const table = (
      result.value.result as unknown as {
        readonly tables: readonly Record<string, unknown>[];
      }
    ).tables[0];
    expect(table).toMatchObject({
      name: "sms.tsv",
      columns: ["id", "body"],
      rows: [["1", "hello"]],
      truncated: false,
    });
  });

  it("refuses an output directory that does not exist", async () => {
    const apk = await apkFixture();
    const provider = new MobileToolchainProvider({
      environment: { [ILEAPP_COMMAND_ENV]: "/opt/rea/ileapp" },
      run: fakeRunner(() => completed("")).run,
    });
    const result = await provider.execute({
      operation: "run_mobile_forensics_report",
      input: {
        input_path: apk,
        output_directory: "/nonexistent-rea-output",
        platform: "ios",
        max_tables: 48,
        max_rows_per_table: 200,
        timeout_ms: 300_000,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });
});

describe("mobile toolchain readiness", () => {
  it("reports a missing launcher as not configured and a probed one as available", async () => {
    const absent = new MobileToolchainProvider({
      environment: {},
      run: fakeRunner(() => completed("")).run,
    });
    const missing = await absent.inspectAvailability("objection");
    expect(missing.status).toBe("unavailable");
    expect(missing.code).toBe("not_configured");

    const present = new MobileToolchainProvider({
      environment: { [OBJECTION_COMMAND_ENV]: "/opt/rea/objection" },
      run: fakeRunner(() => completed("objection: 1.11.0\n")).run,
    });
    const available = await present.inspectAvailability("objection");
    expect(available.status).toBe("available");
    expect(available.diagnostics.version).toBe("1.11.0");
  });
});
