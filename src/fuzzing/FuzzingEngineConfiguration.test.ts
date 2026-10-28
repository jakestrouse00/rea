import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  FUZZING_AFLFRIDA_COMMAND_ENV,
  FUZZING_JACKALOPE_DIR_ENV,
  FUZZING_JACKALOPE_FUZZER_FILE,
  FUZZING_JACKALOPE_INSTRUMENTATION_FILE,
  FUZZING_LFZ_COMMAND_ENV,
} from "../domain/fuzzing/fuzzingEngine.js";
import {
  FuzzingEngineConfigurationFailure,
  fuzzingEngineAvailability,
  inspectFuzzingEngines,
  resolveFuzzingEngineConfiguration,
} from "./FuzzingEngineConfiguration.js";

const darwinArm64 = { platform: "darwin" as const, arch: "arm64" };

const failureOf = (
  action: () => unknown,
): FuzzingEngineConfigurationFailure => {
  try {
    action();
  } catch (cause: unknown) {
    if (cause instanceof FuzzingEngineConfigurationFailure) return cause;
    throw cause;
  }
  throw new Error("Expected a configuration refusal");
};

const engineFile = async (directory: string, name: string, mode: number) => {
  const path = join(directory, name);
  await writeFile(path, "#!/bin/sh\nexit 0\n", { mode });
  return path;
};

describe("fuzzing engine configuration", () => {
  it("refuses an engine nobody selected", () => {
    const failure = failureOf(() =>
      resolveFuzzingEngineConfiguration({}, "libfuzzer"),
    );
    expect(failure.code).toBe("engine_not_configured");
    expect(failure.setting).toBe(FUZZING_LFZ_COMMAND_ENV);
    expect(failure.remediation).toContain(FUZZING_LFZ_COMMAND_ENV);
  });

  it("refuses a relative selection without probing it", () => {
    const failure = failureOf(() =>
      resolveFuzzingEngineConfiguration(
        { [FUZZING_LFZ_COMMAND_ENV]: "bin/fuzz_target" },
        "libfuzzer",
      ),
    );
    expect(failure.code).toBe("not_absolute");
    expect(failure.diagnostics).toMatchObject({
      configured_path: "bin/fuzz_target",
    });
  });

  it("refuses a missing and a non-executable selection", async () => {
    const directory = await createTestTempDirectory("fuzzing-config-");
    const missing = failureOf(() =>
      resolveFuzzingEngineConfiguration(
        { [FUZZING_LFZ_COMMAND_ENV]: join(directory, "absent") },
        "libfuzzer",
      ),
    );
    expect(missing.code).toBe("binary_missing");

    const plain = await engineFile(directory, "not-executable", 0o600);
    const denied = failureOf(() =>
      resolveFuzzingEngineConfiguration(
        { [FUZZING_LFZ_COMMAND_ENV]: plain },
        "libfuzzer",
      ),
    );
    expect(denied.code).toBe("binary_not_executable");
  });

  it("resolves an absolute executable selection", async () => {
    const directory = await createTestTempDirectory("fuzzing-config-");
    const command = await engineFile(directory, "fuzz_target", 0o700);
    const resolved = resolveFuzzingEngineConfiguration(
      { [FUZZING_LFZ_COMMAND_ENV]: command },
      "libfuzzer",
    );
    expect(resolved).toEqual({
      engine: "libfuzzer",
      command,
      supportDirectory: null,
    });
  });

  it("requires the Jackalope build tree's fuzzer and instrumentation", async () => {
    const directory = await createTestTempDirectory("fuzzing-jackalope-");
    const build = join(directory, "build");
    await mkdir(build);
    await engineFile(build, FUZZING_JACKALOPE_FUZZER_FILE, 0o700);
    const incomplete = failureOf(() =>
      resolveFuzzingEngineConfiguration(
        { [FUZZING_JACKALOPE_DIR_ENV]: build },
        "jackalope",
      ),
    );
    expect(incomplete.code).toBe("build_missing");
    expect(incomplete.message).toContain(
      FUZZING_JACKALOPE_INSTRUMENTATION_FILE,
    );

    await writeFile(
      join(build, FUZZING_JACKALOPE_INSTRUMENTATION_FILE),
      "dylib",
    );
    expect(
      resolveFuzzingEngineConfiguration(
        { [FUZZING_JACKALOPE_DIR_ENV]: build },
        "jackalope",
      ),
    ).toMatchObject({ engine: "jackalope", supportDirectory: build });
  });

  it("keeps AFL++ FRIDA host execution on macOS arm64", async () => {
    const directory = await createTestTempDirectory("fuzzing-afl-");
    const command = await engineFile(directory, "afl-fuzz", 0o700);
    const environment = { [FUZZING_AFLFRIDA_COMMAND_ENV]: command };
    const unsupported = failureOf(() =>
      resolveFuzzingEngineConfiguration(environment, "aflpp_frida", {
        platform: "linux",
        arch: "aarch64",
      }),
    );
    expect(unsupported.code).toBe("unsupported_host");
    expect(
      resolveFuzzingEngineConfiguration(
        environment,
        "aflpp_frida",
        darwinArm64,
      ),
    ).toMatchObject({ engine: "aflpp_frida", command });
  });

  it("reports one configured engine without claiming the others", async () => {
    const directory = await createTestTempDirectory("fuzzing-avail-");
    const command = await engineFile(directory, "fuzz_target", 0o700);
    const environment = { [FUZZING_LFZ_COMMAND_ENV]: command };
    const availability = fuzzingEngineAvailability(environment, darwinArm64);
    expect(availability.status).toBe("available");
    expect(availability.diagnostics).toMatchObject({ engines: ["libfuzzer"] });
    expect(inspectFuzzingEngines(environment, darwinArm64)).toMatchObject([
      { engine: "libfuzzer", available: true },
      { engine: "aflpp_frida", available: false },
      { engine: "jackalope", available: false },
    ]);
    const none = fuzzingEngineAvailability({}, darwinArm64);
    expect(none.status).toBe("unavailable");
    expect(none.code).toBe("not_configured");
    expect(none.reason).toContain(FUZZING_JACKALOPE_DIR_ENV);
  });
});
