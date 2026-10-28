import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  readLiefConfiguration,
  resolveLiefConfiguration,
} from "./LiefConfiguration.js";
import {
  LIEF_BRIDGE_DIR_ENV,
  LIEF_BRIDGE_DIR_REMEDIATION,
  LIEF_BRIDGE_FILE_NAME,
  LIEF_COMMAND_ENV,
  LIEF_COMMAND_REMEDIATION,
} from "../domain/lief/liefLimits.js";

const selectedDirectory = async (): Promise<string> =>
  mkdtemp(join(tmpdir(), "rea-lief-config-"));

const executable = async (directory: string): Promise<string> => {
  const path = join(directory, "python3");
  await writeFile(path, "#!/bin/sh\nexit 0\n");
  await chmod(path, 0o755);
  return path;
};

describe("readLiefConfiguration", () => {
  it("refuses an unset interpreter with its own setting and remediation", () => {
    const parsed = readLiefConfiguration({});
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected refusal");
    expect(parsed.error).toMatchObject({
      code: "not_configured",
      setting: LIEF_COMMAND_ENV,
      remediation: LIEF_COMMAND_REMEDIATION,
    });
  });

  it("refuses a relative interpreter path", () => {
    const parsed = readLiefConfiguration({
      [LIEF_COMMAND_ENV]: "python3",
      [LIEF_BRIDGE_DIR_ENV]: "/opt/rea-lief",
    });
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected refusal");
    expect(parsed.error.code).toBe("not_absolute");
    expect(parsed.error.setting).toBe(LIEF_COMMAND_ENV);
  });

  it("refuses an unset bridge directory", () => {
    const parsed = readLiefConfiguration({
      [LIEF_COMMAND_ENV]: "/usr/bin/python3",
    });
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected refusal");
    expect(parsed.error).toMatchObject({
      code: "not_configured",
      setting: LIEF_BRIDGE_DIR_ENV,
      remediation: LIEF_BRIDGE_DIR_REMEDIATION,
    });
  });

  it("resolves both settings without touching the filesystem", () => {
    const parsed = readLiefConfiguration({
      [LIEF_COMMAND_ENV]: "/usr/bin/python3",
      [LIEF_BRIDGE_DIR_ENV]: "/opt/rea-lief",
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) throw new Error(parsed.error.reason);
    expect(parsed.value.bridgePath).toBe(
      join("/opt/rea-lief", LIEF_BRIDGE_FILE_NAME),
    );
    expect(parsed.value.protocolVersion).toBe(1);
  });
});

describe("resolveLiefConfiguration", () => {
  it("reports a missing interpreter as its own refusal code", async () => {
    const directory = await selectedDirectory();
    const resolved = resolveLiefConfiguration({
      [LIEF_COMMAND_ENV]: join(directory, "absent-python"),
      [LIEF_BRIDGE_DIR_ENV]: directory,
    });
    expect(resolved.ok).toBe(false);
    if (resolved.ok) throw new Error("expected refusal");
    expect(resolved.error.code).toBe("command_missing");
  });

  it("reports a non-executable selection instead of a missing one", async () => {
    const directory = await selectedDirectory();
    const path = join(directory, "not-executable");
    await writeFile(path, "");
    const resolved = resolveLiefConfiguration({
      [LIEF_COMMAND_ENV]: path,
      [LIEF_BRIDGE_DIR_ENV]: directory,
    });
    expect(resolved.ok).toBe(false);
    if (resolved.ok) throw new Error("expected refusal");
    expect(resolved.error.code).toBe("command_not_executable");
  });

  it("reports a missing bridge directory before any process starts", async () => {
    const directory = await selectedDirectory();
    const command = await executable(directory);
    const resolved = resolveLiefConfiguration({
      [LIEF_COMMAND_ENV]: command,
      [LIEF_BRIDGE_DIR_ENV]: join(directory, "absent"),
    });
    expect(resolved.ok).toBe(false);
    if (resolved.ok) throw new Error("expected refusal");
    expect(resolved.error.code).toBe("bridge_directory_missing");
  });

  it("reports a directory without the bridge script", async () => {
    const directory = await selectedDirectory();
    const command = await executable(directory);
    const resolved = resolveLiefConfiguration({
      [LIEF_COMMAND_ENV]: command,
      [LIEF_BRIDGE_DIR_ENV]: directory,
    });
    expect(resolved.ok).toBe(false);
    if (resolved.ok) throw new Error("expected refusal");
    expect(resolved.error.code).toBe("bridge_script_not_found");
  });

  it("resolves a selected interpreter and bridge script", async () => {
    const directory = await selectedDirectory();
    const command = await executable(directory);
    await writeFile(join(directory, LIEF_BRIDGE_FILE_NAME), "# bridge\n");
    const resolved = resolveLiefConfiguration({
      [LIEF_COMMAND_ENV]: command,
      [LIEF_BRIDGE_DIR_ENV]: directory,
    });
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) throw new Error(resolved.error.reason);
    expect(resolved.value).toMatchObject({
      command,
      bridgeDirectory: directory,
      bridgePath: join(directory, LIEF_BRIDGE_FILE_NAME),
    });
  });
});
