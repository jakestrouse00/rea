import { expect, test } from "vitest";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  emuConfigurationAvailability,
  emuLaneConfigured,
  EmuConfigurationFailure,
  resolveEmuConfiguration,
} from "./EmuConfiguration.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";

const bridgeDirectory = async (root: string): Promise<string> => {
  const directory = join(root, "bridge");
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "unicorn_bridge.py"), "# bridge\n");
  return directory;
};

const interpreter = async (root: string): Promise<string> => {
  const path = join(root, "python-fixture");
  await writeFile(path, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  return path;
};

const failureOf = (environment: Readonly<Record<string, string>>) => {
  try {
    resolveEmuConfiguration(environment);
  } catch (cause: unknown) {
    if (cause instanceof EmuConfigurationFailure) return cause;
    throw cause;
  }
  throw new Error("expected a configuration failure");
};

test("resolves the caller's interpreter and bridge directory", async () => {
  const root = await createTestTempDirectory("rea-emu-config-");
  const python = await interpreter(root);
  const directory = await bridgeDirectory(root);
  const configuration = resolveEmuConfiguration({
    REA_UNICORN_PYTHON: python,
    REA_UNICORN_BRIDGE_DIR: directory,
  });
  expect(configuration).toEqual({
    python,
    bridgeDirectory: directory,
    bridgeScript: join(directory, "unicorn_bridge.py"),
  });
  expect(
    emuLaneConfigured({
      REA_UNICORN_PYTHON: python,
      REA_UNICORN_BRIDGE_DIR: directory,
    }),
  ).toBe(true);
});

test("fails closed when the interpreter is unset", () => {
  const failure = failureOf({});
  expect(failure.code).toBe("not_configured");
  expect(failure.message).toContain("REA_UNICORN_PYTHON");
  expect(failure.diagnostics).toMatchObject({
    setting: "REA_UNICORN_PYTHON",
    remediation: expect.stringContaining("docs/emulation.md") as unknown,
  });
  expect(emuLaneConfigured({})).toBe(false);
});

test("refuses a relative interpreter or bridge directory", async () => {
  const root = await createTestTempDirectory("rea-emu-config-");
  const directory = await bridgeDirectory(root);
  const relativeInterpreter = failureOf({
    REA_UNICORN_PYTHON: "python3",
    REA_UNICORN_BRIDGE_DIR: directory,
  });
  expect(relativeInterpreter.code).toBe("not_absolute");
  expect(relativeInterpreter.diagnostics).toMatchObject({
    setting: "REA_UNICORN_PYTHON",
  });
  const python = await interpreter(root);
  const relativeDirectory = failureOf({
    REA_UNICORN_PYTHON: python,
    REA_UNICORN_BRIDGE_DIR: "bridge",
  });
  expect(relativeDirectory.code).toBe("not_absolute");
  expect(relativeDirectory.diagnostics).toMatchObject({
    setting: "REA_UNICORN_BRIDGE_DIR",
  });
});

test("refuses an interpreter that is missing or not executable", async () => {
  const root = await createTestTempDirectory("rea-emu-config-");
  const directory = await bridgeDirectory(root);
  const missing = failureOf({
    REA_UNICORN_PYTHON: join(root, "absent-python"),
    REA_UNICORN_BRIDGE_DIR: directory,
  });
  expect(missing.code).toBe("python_missing");
  const notExecutable = join(root, "plain-file");
  await writeFile(notExecutable, "not a program\n");
  await chmod(notExecutable, 0o644);
  const denied = failureOf({
    REA_UNICORN_PYTHON: notExecutable,
    REA_UNICORN_BRIDGE_DIR: directory,
  });
  expect(denied.code).toBe("python_not_executable");
});

test("refuses a missing bridge directory or script", async () => {
  const root = await createTestTempDirectory("rea-emu-config-");
  const python = await interpreter(root);
  const missingDirectory = failureOf({
    REA_UNICORN_PYTHON: python,
    REA_UNICORN_BRIDGE_DIR: join(root, "absent"),
  });
  expect(missingDirectory.code).toBe("bridge_directory_missing");
  const empty = join(root, "empty-bridge");
  await mkdir(empty, { recursive: true });
  const missingScript = failureOf({
    REA_UNICORN_PYTHON: python,
    REA_UNICORN_BRIDGE_DIR: empty,
  });
  expect(missingScript.code).toBe("bridge_script_missing");
  expect(missingScript.diagnostics).toMatchObject({
    setting: "REA_UNICORN_BRIDGE_DIR",
    bridge_script: join(empty, "unicorn_bridge.py"),
  });
});

test("projects a configuration failure into availability", () => {
  const failure = failureOf({});
  expect(emuConfigurationAvailability(failure)).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
});
