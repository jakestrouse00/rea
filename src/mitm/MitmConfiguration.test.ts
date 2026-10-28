import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  MITM_ADDON_DIR_ENV,
  MITM_ADDON_DIR_REMEDIATION,
  MITM_ADDON_FILE_NAME,
  MITM_COMMAND_ENV,
  MITM_COMMAND_REMEDIATION,
} from "../domain/mitm/mitmLimits.js";
import {
  MitmConfigurationFailure,
  mitmConfigurationAvailability,
  mitmInterceptionConfigured,
  resolveMitmConfiguration,
} from "./MitmConfiguration.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

interface Layout {
  readonly command: string;
  readonly addonDirectory: string;
  readonly addonPath: string;
}

const layout = async (): Promise<Layout> => {
  const root = await createTestTempDirectory("mitm-config-");
  roots.push(root);
  const command = join(root, "mitmdump");
  const addonDirectory = join(root, "addon");
  await mkdir(addonDirectory, { recursive: true });
  await writeFile(command, "#!/bin/sh\n", { mode: 0o700 });
  await chmod(command, 0o700);
  const addonPath = join(addonDirectory, MITM_ADDON_FILE_NAME);
  await writeFile(addonPath, "# addon\n", { mode: 0o644 });
  return { command, addonDirectory, addonPath };
};

const refusal = (
  environment: Readonly<Record<string, string | undefined>>,
): MitmConfigurationFailure => {
  try {
    resolveMitmConfiguration(environment);
  } catch (cause: unknown) {
    if (cause instanceof MitmConfigurationFailure) return cause;
    throw cause;
  }
  throw new Error("The configuration resolved when it should have refused");
};

describe("interception configuration", () => {
  it("resolves an absolute mitmdump and generated addon", async () => {
    const files = await layout();
    const resolved = resolveMitmConfiguration({
      [MITM_COMMAND_ENV]: files.command,
      [MITM_ADDON_DIR_ENV]: files.addonDirectory,
    });
    expect(resolved.command).toBe(files.command);
    expect(resolved.addonPath).toBe(files.addonPath);
    expect(resolved.startTimeoutMs).toBeGreaterThan(0);
    expect(
      mitmInterceptionConfigured({
        [MITM_COMMAND_ENV]: files.command,
        [MITM_ADDON_DIR_ENV]: files.addonDirectory,
      }),
    ).toBe(true);
  });

  it("refuses an unset or empty mitmdump selection", async () => {
    const files = await layout();
    for (const environment of [
      { [MITM_ADDON_DIR_ENV]: files.addonDirectory },
      { [MITM_COMMAND_ENV]: "  ", [MITM_ADDON_DIR_ENV]: files.addonDirectory },
    ]) {
      const cause = refusal(environment);
      expect(cause.code).toBe("not_configured");
      expect(cause.diagnostics.setting).toBe(MITM_COMMAND_ENV);
      expect(cause.diagnostics.remediation).toBe(MITM_COMMAND_REMEDIATION);
      expect(mitmInterceptionConfigured(environment)).toBe(false);
    }
  });

  it("refuses a relative mitmdump path", async () => {
    const files = await layout();
    const cause = refusal({
      [MITM_COMMAND_ENV]: "mitmdump",
      [MITM_ADDON_DIR_ENV]: files.addonDirectory,
    });
    expect(cause.code).toBe("not_absolute");
    expect(cause.diagnostics.setting).toBe(MITM_COMMAND_ENV);
  });

  it("distinguishes a missing binary from a denied one", async () => {
    const files = await layout();
    const missing = refusal({
      [MITM_COMMAND_ENV]: join(files.addonDirectory, "absent"),
      [MITM_ADDON_DIR_ENV]: files.addonDirectory,
    });
    expect(missing.code).toBe("command_missing");
    const denied = join(files.addonDirectory, "denied");
    await writeFile(denied, "#!/bin/sh\n", { mode: 0o600 });
    await chmod(denied, 0o600);
    const unexecutable = refusal({
      [MITM_COMMAND_ENV]: denied,
      [MITM_ADDON_DIR_ENV]: files.addonDirectory,
    });
    expect(unexecutable.code).toBe("command_not_executable");
  });

  it("refuses an unset, relative, or missing addon directory", async () => {
    const files = await layout();
    const unset = refusal({ [MITM_COMMAND_ENV]: files.command });
    expect(unset.code).toBe("not_configured");
    expect(unset.diagnostics.setting).toBe(MITM_ADDON_DIR_ENV);
    expect(unset.diagnostics.remediation).toBe(MITM_ADDON_DIR_REMEDIATION);
    const relative = refusal({
      [MITM_COMMAND_ENV]: files.command,
      [MITM_ADDON_DIR_ENV]: "addon",
    });
    expect(relative.code).toBe("not_absolute");
    const missing = refusal({
      [MITM_COMMAND_ENV]: files.command,
      [MITM_ADDON_DIR_ENV]: join(files.addonDirectory, "absent"),
    });
    expect(missing.code).toBe("addon_directory_missing");
  });

  it("refuses a directory without the generated addon", async () => {
    const files = await layout();
    await rm(files.addonPath);
    const cause = refusal({
      [MITM_COMMAND_ENV]: files.command,
      [MITM_ADDON_DIR_ENV]: files.addonDirectory,
    });
    expect(cause.code).toBe("addon_not_found");
    expect(cause.diagnostics.remediation).toBe(MITM_ADDON_DIR_REMEDIATION);
  });

  it("projects a refusal into provider availability", async () => {
    const availability = mitmConfigurationAvailability(
      new MitmConfigurationFailure("not_configured", "unset", {
        setting: MITM_COMMAND_ENV,
      }),
    );
    expect(availability).toMatchObject({
      status: "unavailable",
      code: "not_configured",
      reason: "unset",
    });
  });
});
