import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  EMU_BRIDGE_DIR_ENV,
  EMU_BRIDGE_DIR_REMEDIATION,
  EMU_BRIDGE_FILE_NAME,
  EMU_PYTHON_ENV,
  EMU_PYTHON_ENV_REMEDIATION,
} from "../domain/emu/emuLimits.js";

/** One resolved emulation-lane selection. */
export interface EmuConfiguration {
  /** Interpreter of the caller-managed environment carrying Unicorn 2.1.x. */
  readonly python: string;
  readonly bridgeDirectory: string;
  readonly bridgeScript: string;
}

export type EmuConfigurationFailureCode =
  | "not_configured"
  | "not_absolute"
  | "python_missing"
  | "python_not_executable"
  | "bridge_directory_missing"
  | "bridge_script_missing";

export class EmuConfigurationFailure extends Error {
  readonly _tag = "EmuConfigurationFailure";
  constructor(
    readonly code: EmuConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "EmuConfigurationFailure";
  }
}

const failure = (
  code: EmuConfigurationFailureCode,
  message: string,
  diagnostics: Readonly<Record<string, JsonValue>>,
  cause?: unknown,
): EmuConfigurationFailure =>
  new EmuConfigurationFailure(
    code,
    message,
    diagnostics,
    cause === undefined ? undefined : { cause },
  );

const pythonFailure = (python: string): EmuConfigurationFailure | null => {
  try {
    accessSync(python, constants.X_OK);
    if (!statSync(python).isFile())
      return failure(
        "python_not_executable",
        `The selected interpreter is not a regular file: ${python}`,
        {
          setting: EMU_PYTHON_ENV,
          selected_interpreter: python,
          remediation: EMU_PYTHON_ENV_REMEDIATION,
        },
      );
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    const denied = code === "EACCES" || code === "EPERM";
    return failure(
      denied ? "python_not_executable" : "python_missing",
      denied
        ? `Execution of the selected interpreter was denied: ${python}`
        : `The selected interpreter was not found: ${python}`,
      {
        setting: EMU_PYTHON_ENV,
        selected_interpreter: python,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: EMU_PYTHON_ENV_REMEDIATION,
      },
      cause,
    );
  }
};

const bridgeFailure = (directory: string): EmuConfigurationFailure | null => {
  try {
    if (!statSync(directory).isDirectory())
      return failure(
        "bridge_directory_missing",
        `The selected bridge directory is not a directory: ${directory}`,
        {
          setting: EMU_BRIDGE_DIR_ENV,
          configured_path: directory,
          remediation: EMU_BRIDGE_DIR_REMEDIATION,
        },
      );
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    return failure(
      "bridge_directory_missing",
      `The selected bridge directory was not found: ${directory}`,
      {
        setting: EMU_BRIDGE_DIR_ENV,
        configured_path: directory,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: EMU_BRIDGE_DIR_REMEDIATION,
      },
      cause,
    );
  }
  const script = join(directory, EMU_BRIDGE_FILE_NAME);
  try {
    if (!statSync(script).isFile())
      return failure(
        "bridge_script_missing",
        `The bridge script is not a regular file: ${script}`,
        {
          setting: EMU_BRIDGE_DIR_ENV,
          bridge_script: script,
          remediation: EMU_BRIDGE_DIR_REMEDIATION,
        },
      );
    accessSync(script, constants.R_OK);
    return null;
  } catch (cause: unknown) {
    return failure(
      "bridge_script_missing",
      `The bridge script ${EMU_BRIDGE_FILE_NAME} was not found in ${directory}`,
      {
        setting: EMU_BRIDGE_DIR_ENV,
        bridge_script: script,
        remediation: EMU_BRIDGE_DIR_REMEDIATION,
      },
      cause,
    );
  }
};

/** Resolve the caller-supplied interpreter and bridge directory, fail-closed. */
export const resolveEmuConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): EmuConfiguration => {
  const python = environment[EMU_PYTHON_ENV];
  if (python === undefined || python.trim() === "")
    throw failure(
      "not_configured",
      `No emulation interpreter is selected: ${EMU_PYTHON_ENV} is unset`,
      {
        setting: EMU_PYTHON_ENV,
        remediation: EMU_PYTHON_ENV_REMEDIATION,
      },
    );
  if (!isAbsolute(python))
    throw failure(
      "not_absolute",
      `${EMU_PYTHON_ENV} must be an absolute path to the Python interpreter`,
      {
        setting: EMU_PYTHON_ENV,
        configured_path: python,
        remediation: EMU_PYTHON_ENV_REMEDIATION,
      },
    );
  const directory = environment[EMU_BRIDGE_DIR_ENV];
  if (directory === undefined || directory.trim() === "")
    throw failure(
      "not_configured",
      `No bridge directory is selected: ${EMU_BRIDGE_DIR_ENV} is unset`,
      {
        setting: EMU_BRIDGE_DIR_ENV,
        remediation: EMU_BRIDGE_DIR_REMEDIATION,
      },
    );
  if (!isAbsolute(directory))
    throw failure(
      "not_absolute",
      `${EMU_BRIDGE_DIR_ENV} must be an absolute path to the directory holding ${EMU_BRIDGE_FILE_NAME}`,
      {
        setting: EMU_BRIDGE_DIR_ENV,
        configured_path: directory,
        remediation: EMU_BRIDGE_DIR_REMEDIATION,
      },
    );
  const pythonProblem = pythonFailure(python);
  if (pythonProblem !== null) throw pythonProblem;
  const bridgeProblem = bridgeFailure(directory);
  if (bridgeProblem !== null) throw bridgeProblem;
  return {
    python,
    bridgeDirectory: directory,
    bridgeScript: join(directory, EMU_BRIDGE_FILE_NAME),
  };
};

/** Whether this host can be asked to run the lane at all. */
export const emuLaneConfigured = (
  environment: Readonly<Record<string, string | undefined>>,
): boolean => {
  try {
    resolveEmuConfiguration(environment);
    return true;
  } catch {
    return false;
  }
};

const rejectionCodeOf = (
  code: EmuConfigurationFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "python_missing":
    case "bridge_directory_missing":
    case "bridge_script_missing":
      return "executable_missing";
    case "python_not_executable":
    case "not_configured":
    case "not_absolute":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const emuConfigurationAvailability = (
  cause: EmuConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
