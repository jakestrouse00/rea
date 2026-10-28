import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

import type { JsonValue } from "../domain/jsonValue.js";
import {
  CRASH_MINIMIZE_AFLTMIN_COMMAND_ENV,
  CRASH_MINIMIZE_AFLTMIN_REMEDIATION,
  CRASH_MINIMIZE_LFZ_COMMAND_ENV,
  CRASH_MINIMIZE_LFZ_REMEDIATION,
  type CrashMinimizeEngine,
} from "../domain/crashTriage/crashMinimization.js";

/** One resolved minimizer selection. */
export interface CrashMinimizeConfiguration {
  readonly engine: CrashMinimizeEngine;
  readonly command: string;
}

export type CrashMinimizeConfigurationCode =
  | "engine_not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable";

/** A minimizer selection that cannot be used as configured. */
export class CrashMinimizeConfigurationFailure extends Error {
  readonly _tag = "CrashMinimizeConfigurationFailure";
  constructor(
    readonly engine: CrashMinimizeEngine,
    readonly code: CrashMinimizeConfigurationCode,
    message: string,
    readonly setting: string,
    readonly remediation: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "CrashMinimizeConfigurationFailure";
  }
}

const settingFor = (engine: CrashMinimizeEngine): string =>
  engine === "libfuzzer"
    ? CRASH_MINIMIZE_LFZ_COMMAND_ENV
    : CRASH_MINIMIZE_AFLTMIN_COMMAND_ENV;

const remediationFor = (engine: CrashMinimizeEngine): string =>
  engine === "libfuzzer"
    ? CRASH_MINIMIZE_LFZ_REMEDIATION
    : CRASH_MINIMIZE_AFLTMIN_REMEDIATION;

const executableFailure = (
  engine: CrashMinimizeEngine,
  command: string,
): CrashMinimizeConfigurationFailure | null => {
  const setting = settingFor(engine);
  const remediation = remediationFor(engine);
  try {
    accessSync(command, constants.X_OK);
    if (!statSync(command).isFile())
      return new CrashMinimizeConfigurationFailure(
        engine,
        "binary_not_executable",
        `The selected minimizer path is not a regular file: ${command}`,
        setting,
        remediation,
        { selected_binary: command },
      );
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    const denied = code === "EACCES" || code === "EPERM";
    return new CrashMinimizeConfigurationFailure(
      engine,
      denied ? "binary_not_executable" : "binary_missing",
      denied
        ? `Execution of the selected minimizer binary was denied: ${command}`
        : `The selected minimizer binary was not found: ${command}`,
      setting,
      remediation,
      {
        selected_binary: command,
        ...(code === undefined ? {} : { filesystem_error: code }),
      },
      { cause },
    );
  }
};

/**
 * Resolve the caller-supplied minimizer for one engine, fail-closed.
 *
 * REA never builds, downloads, or upgrades a fuzz target or an AFL++ binary.
 * An unconfigured engine stays usable by every other campaign tool; only the
 * minimization hook refuses.
 */
export const resolveCrashMinimizeConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
  engine: CrashMinimizeEngine,
): CrashMinimizeConfiguration => {
  const setting = settingFor(engine);
  const command = environment[setting];
  if (command === undefined || command.trim() === "")
    throw new CrashMinimizeConfigurationFailure(
      engine,
      "engine_not_configured",
      `No minimizer is selected: ${setting} is unset`,
      setting,
      remediationFor(engine),
    );
  if (!isAbsolute(command))
    throw new CrashMinimizeConfigurationFailure(
      engine,
      "not_absolute",
      `${setting} must be an absolute path to the minimizer binary`,
      setting,
      remediationFor(engine),
      { configured_path: command },
    );
  const failure = executableFailure(engine, command);
  if (failure !== null) throw failure;
  return { engine, command };
};
