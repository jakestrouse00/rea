import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  MITM_ADDON_DIR_ENV,
  MITM_ADDON_DIR_REMEDIATION,
  MITM_ADDON_FILE_NAME,
  MITM_COMMAND_ENV,
  MITM_COMMAND_REMEDIATION,
  MITM_LIMITS,
} from "../domain/mitm/mitmLimits.js";

/** One resolved interception-lane selection. */
export interface MitmConfiguration {
  readonly command: string;
  readonly addonPath: string;
  readonly addonDirectory: string;
  readonly startTimeoutMs: number;
}

export type MitmConfigurationFailureCode =
  | "not_configured"
  | "not_absolute"
  | "command_missing"
  | "command_not_executable"
  | "addon_directory_missing"
  | "addon_not_found";

export class MitmConfigurationFailure extends Error {
  readonly _tag = "MitmConfigurationFailure";
  constructor(
    readonly code: MitmConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "MitmConfigurationFailure";
  }
}

const failure = (
  code: MitmConfigurationFailureCode,
  message: string,
  diagnostics: Readonly<Record<string, JsonValue>>,
  cause?: unknown,
): MitmConfigurationFailure =>
  new MitmConfigurationFailure(
    code,
    message,
    diagnostics,
    cause === undefined ? undefined : { cause },
  );

const commandFailure = (command: string): MitmConfigurationFailure | null => {
  try {
    accessSync(command, constants.X_OK);
    if (!statSync(command).isFile())
      return failure(
        "command_not_executable",
        `The selected mitmdump path is not a regular file: ${command}`,
        {
          setting: MITM_COMMAND_ENV,
          selected_binary: command,
          remediation: MITM_COMMAND_REMEDIATION,
        },
      );
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    const denied = code === "EACCES" || code === "EPERM";
    return failure(
      denied ? "command_not_executable" : "command_missing",
      denied
        ? `Execution of the selected mitmdump binary was denied: ${command}`
        : `The selected mitmdump binary was not found: ${command}`,
      {
        setting: MITM_COMMAND_ENV,
        selected_binary: command,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: MITM_COMMAND_REMEDIATION,
      },
      cause,
    );
  }
};

const addonFailure = (directory: string): MitmConfigurationFailure | null => {
  try {
    if (!statSync(directory).isDirectory())
      return failure(
        "addon_directory_missing",
        `The selected addon directory is not a directory: ${directory}`,
        {
          setting: MITM_ADDON_DIR_ENV,
          configured_path: directory,
          remediation: MITM_ADDON_DIR_REMEDIATION,
        },
      );
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    return failure(
      "addon_directory_missing",
      `The selected addon directory was not found: ${directory}`,
      {
        setting: MITM_ADDON_DIR_ENV,
        configured_path: directory,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: MITM_ADDON_DIR_REMEDIATION,
      },
      cause,
    );
  }
  const addonPath = join(directory, MITM_ADDON_FILE_NAME);
  try {
    if (!statSync(addonPath).isFile())
      return failure(
        "addon_not_found",
        `The addon is not a regular file: ${addonPath}`,
        {
          setting: MITM_ADDON_DIR_ENV,
          addon_path: addonPath,
          remediation: MITM_ADDON_DIR_REMEDIATION,
        },
      );
    accessSync(addonPath, constants.R_OK);
    return null;
  } catch (cause: unknown) {
    return failure(
      "addon_not_found",
      `The generated addon ${MITM_ADDON_FILE_NAME} was not found in ${directory}`,
      {
        setting: MITM_ADDON_DIR_ENV,
        addon_path: addonPath,
        remediation: MITM_ADDON_DIR_REMEDIATION,
      },
      cause,
    );
  }
};

/** Resolve the caller-supplied mitmdump and generated addon, fail-closed. */
export const resolveMitmConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): MitmConfiguration => {
  const command = environment[MITM_COMMAND_ENV];
  if (command === undefined || command.trim() === "")
    throw failure(
      "not_configured",
      `No mitmdump binary is selected: ${MITM_COMMAND_ENV} is unset`,
      {
        setting: MITM_COMMAND_ENV,
        remediation: MITM_COMMAND_REMEDIATION,
      },
    );
  if (!isAbsolute(command))
    throw failure(
      "not_absolute",
      `${MITM_COMMAND_ENV} must be an absolute path to the mitmdump binary`,
      {
        setting: MITM_COMMAND_ENV,
        configured_path: command,
        remediation: MITM_COMMAND_REMEDIATION,
      },
    );
  const directory = environment[MITM_ADDON_DIR_ENV];
  if (directory === undefined || directory.trim() === "")
    throw failure(
      "not_configured",
      `No addon directory is selected: ${MITM_ADDON_DIR_ENV} is unset`,
      {
        setting: MITM_ADDON_DIR_ENV,
        remediation: MITM_ADDON_DIR_REMEDIATION,
      },
    );
  if (!isAbsolute(directory))
    throw failure(
      "not_absolute",
      `${MITM_ADDON_DIR_ENV} must be an absolute path to the directory holding ${MITM_ADDON_FILE_NAME}`,
      {
        setting: MITM_ADDON_DIR_ENV,
        configured_path: directory,
        remediation: MITM_ADDON_DIR_REMEDIATION,
      },
    );
  const commandProblem = commandFailure(command);
  if (commandProblem !== null) throw commandProblem;
  const addonProblem = addonFailure(directory);
  if (addonProblem !== null) throw addonProblem;
  return {
    command,
    addonDirectory: directory,
    addonPath: join(directory, MITM_ADDON_FILE_NAME),
    startTimeoutMs: MITM_LIMITS.defaultStartTimeoutMs,
  };
};

/** Whether this host can be asked to start the lane at all. */
export const mitmInterceptionConfigured = (
  environment: Readonly<Record<string, string | undefined>>,
): boolean => {
  try {
    resolveMitmConfiguration(environment);
    return true;
  } catch {
    return false;
  }
};

const rejectionCodeOf = (
  code: MitmConfigurationFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "command_missing":
    case "addon_directory_missing":
    case "addon_not_found":
      return "executable_missing";
    case "command_not_executable":
    case "not_configured":
    case "not_absolute":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const mitmConfigurationAvailability = (
  cause: MitmConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
