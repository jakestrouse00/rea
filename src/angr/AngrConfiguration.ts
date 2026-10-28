import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  ANGR_BRIDGE_DIR_ENV,
  ANGR_BRIDGE_DIR_REMEDIATION,
  ANGR_BRIDGE_FILE_NAME,
  ANGR_JOBS_ENV,
  ANGR_LIMITS,
  ANGR_OPERATION_TIMEOUT_ENV,
  ANGR_OPERATION_TIMEOUT_SETTING,
  ANGR_PYTHON_ENV,
  ANGR_PYTHON_ENV_REMEDIATION,
  DEFAULT_ANGR_OPERATION_TIMEOUT_MS,
} from "../domain/angr/angrLimits.js";

/** One resolved symbolic-lane selection. */
export interface AngrConfiguration {
  /** Interpreter of the caller-managed environment carrying angr. */
  readonly python: string;
  readonly bridgeDirectory: string;
  readonly bridgeScript: string;
  /** Concurrent bridge jobs REA admits for this lane. */
  readonly jobs: number;
  /** Deadline of one job when the request names none. */
  readonly operationTimeoutMs: number;
}

export type AngrConfigurationFailureCode =
  | "not_configured"
  | "not_absolute"
  | "python_missing"
  | "python_not_executable"
  | "bridge_directory_missing"
  | "bridge_script_missing"
  | "jobs_invalid"
  | "timeout_invalid";

export class AngrConfigurationFailure extends Error {
  readonly _tag = "AngrConfigurationFailure";
  constructor(
    readonly code: AngrConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "AngrConfigurationFailure";
  }
}

const failure = (
  code: AngrConfigurationFailureCode,
  message: string,
  diagnostics: Readonly<Record<string, JsonValue>>,
  cause?: unknown,
): AngrConfigurationFailure =>
  new AngrConfigurationFailure(
    code,
    message,
    diagnostics,
    cause === undefined ? undefined : { cause },
  );

/** Largest delay Node schedules exactly, so a deadline never becomes a 1 ms timer. */
const MAX_TIMEOUT_MS = 2_147_483_647;

const positiveInteger = (raw: string | undefined): number | undefined => {
  if (raw === undefined) return undefined;
  if (!/^[0-9]+$/u.test(raw)) return undefined;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed >= 1 ? parsed : undefined;
};

const pythonFailure = (python: string): AngrConfigurationFailure | null => {
  try {
    accessSync(python, constants.X_OK);
    if (!statSync(python).isFile())
      return failure(
        "python_not_executable",
        `The selected interpreter is not a regular file: ${python}`,
        {
          setting: ANGR_PYTHON_ENV,
          selected_interpreter: python,
          remediation: ANGR_PYTHON_ENV_REMEDIATION,
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
        setting: ANGR_PYTHON_ENV,
        selected_interpreter: python,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: ANGR_PYTHON_ENV_REMEDIATION,
      },
      cause,
    );
  }
};

const bridgeFailure = (directory: string): AngrConfigurationFailure | null => {
  try {
    if (!statSync(directory).isDirectory())
      return failure(
        "bridge_directory_missing",
        `The selected bridge directory is not a directory: ${directory}`,
        {
          setting: ANGR_BRIDGE_DIR_ENV,
          configured_path: directory,
          remediation: ANGR_BRIDGE_DIR_REMEDIATION,
        },
      );
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    return failure(
      "bridge_directory_missing",
      `The selected bridge directory was not found: ${directory}`,
      {
        setting: ANGR_BRIDGE_DIR_ENV,
        configured_path: directory,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: ANGR_BRIDGE_DIR_REMEDIATION,
      },
      cause,
    );
  }
  const script = join(directory, ANGR_BRIDGE_FILE_NAME);
  try {
    if (!statSync(script).isFile())
      return failure(
        "bridge_script_missing",
        `The bridge script is not a regular file: ${script}`,
        {
          setting: ANGR_BRIDGE_DIR_ENV,
          bridge_script: script,
          remediation: ANGR_BRIDGE_DIR_REMEDIATION,
        },
      );
    accessSync(script, constants.R_OK);
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    const denied = code === "EACCES" || code === "EPERM";
    return failure(
      "bridge_script_missing",
      denied
        ? `The bridge script ${ANGR_BRIDGE_FILE_NAME} is not readable in ${directory}`
        : `The bridge script ${ANGR_BRIDGE_FILE_NAME} was not found in ${directory}`,
      {
        setting: ANGR_BRIDGE_DIR_ENV,
        bridge_script: script,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: ANGR_BRIDGE_DIR_REMEDIATION,
      },
      cause,
    );
  }
};

/**
 * Resolve the caller-supplied interpreter, bridge directory, concurrency cap,
 * and deadline, fail-closed. The deadline is the runtime setting when one is
 * selected, else the launch environment, else the published default.
 */
export const resolveAngrConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
  settingTimeoutMs?: number,
): AngrConfiguration => {
  const python = environment[ANGR_PYTHON_ENV];
  if (python === undefined || python.trim() === "")
    throw failure(
      "not_configured",
      `No symbolic-execution interpreter is selected: ${ANGR_PYTHON_ENV} is unset`,
      { setting: ANGR_PYTHON_ENV, remediation: ANGR_PYTHON_ENV_REMEDIATION },
    );
  if (!isAbsolute(python))
    throw failure(
      "not_absolute",
      `${ANGR_PYTHON_ENV} must be an absolute path to the Python interpreter`,
      {
        setting: ANGR_PYTHON_ENV,
        configured_path: python,
        remediation: ANGR_PYTHON_ENV_REMEDIATION,
      },
    );
  const directory = environment[ANGR_BRIDGE_DIR_ENV];
  if (directory === undefined || directory.trim() === "")
    throw failure(
      "not_configured",
      `No bridge directory is selected: ${ANGR_BRIDGE_DIR_ENV} is unset`,
      {
        setting: ANGR_BRIDGE_DIR_ENV,
        remediation: ANGR_BRIDGE_DIR_REMEDIATION,
      },
    );
  if (!isAbsolute(directory))
    throw failure(
      "not_absolute",
      `${ANGR_BRIDGE_DIR_ENV} must be an absolute path to the directory holding ${ANGR_BRIDGE_FILE_NAME}`,
      {
        setting: ANGR_BRIDGE_DIR_ENV,
        configured_path: directory,
        remediation: ANGR_BRIDGE_DIR_REMEDIATION,
      },
    );
  const rawJobs = environment[ANGR_JOBS_ENV];
  const jobs = positiveInteger(rawJobs) ?? ANGR_LIMITS.defaultJobs;
  if (jobs > ANGR_LIMITS.maxJobs)
    throw failure(
      "jobs_invalid",
      `${ANGR_JOBS_ENV} must be an integer from 1 to ${String(ANGR_LIMITS.maxJobs)}; received ${String(rawJobs)}`,
      {
        setting: ANGR_JOBS_ENV,
        configured_value: rawJobs ?? null,
        maximum: ANGR_LIMITS.maxJobs,
        remediation: `Set ${ANGR_JOBS_ENV} to an integer from 1 to ${String(ANGR_LIMITS.maxJobs)} and restart REA. Each admitted job owns one angr process, and angr trades memory for exploration width.`,
      },
    );
  if (rawJobs !== undefined && positiveInteger(rawJobs) === undefined)
    throw failure(
      "jobs_invalid",
      `${ANGR_JOBS_ENV} must be an integer from 1 to ${String(ANGR_LIMITS.maxJobs)}; received ${String(rawJobs)}`,
      {
        setting: ANGR_JOBS_ENV,
        configured_value: rawJobs,
        maximum: ANGR_LIMITS.maxJobs,
        remediation: `Set ${ANGR_JOBS_ENV} to an integer from 1 to ${String(ANGR_LIMITS.maxJobs)} and restart REA. Each admitted job owns one angr process, and angr trades memory for exploration width.`,
      },
    );
  const rawTimeout = environment[ANGR_OPERATION_TIMEOUT_ENV];
  const environmentTimeout =
    rawTimeout === undefined
      ? DEFAULT_ANGR_OPERATION_TIMEOUT_MS
      : positiveInteger(rawTimeout);
  if (
    environmentTimeout === undefined ||
    environmentTimeout > MAX_TIMEOUT_MS ||
    (settingTimeoutMs !== undefined &&
      (!Number.isSafeInteger(settingTimeoutMs) || settingTimeoutMs < 1))
  )
    throw failure(
      "timeout_invalid",
      `${ANGR_OPERATION_TIMEOUT_ENV} must be a decimal millisecond count from 1 to ${String(MAX_TIMEOUT_MS)}; received ${String(rawTimeout)}`,
      {
        setting: ANGR_OPERATION_TIMEOUT_ENV,
        runtime_setting: ANGR_OPERATION_TIMEOUT_SETTING,
        configured_value: rawTimeout ?? null,
        maximum: MAX_TIMEOUT_MS,
        remediation: `Set ${ANGR_OPERATION_TIMEOUT_ENV} in REA's launch environment, or use update_analysis_settings with setting ${ANGR_OPERATION_TIMEOUT_SETTING}, then retry.`,
      },
    );
  const pythonProblem = pythonFailure(python);
  if (pythonProblem !== null) throw pythonProblem;
  const bridgeProblem = bridgeFailure(directory);
  if (bridgeProblem !== null) throw bridgeProblem;
  return {
    python,
    bridgeDirectory: directory,
    bridgeScript: join(directory, ANGR_BRIDGE_FILE_NAME),
    jobs,
    operationTimeoutMs: settingTimeoutMs ?? environmentTimeout,
  };
};

/** Whether this host can be asked to run the lane at all. */
export const angrLaneConfigured = (
  environment: Readonly<Record<string, string | undefined>>,
): boolean => {
  try {
    resolveAngrConfiguration(environment);
    return true;
  } catch {
    return false;
  }
};

const rejectionCodeOf = (
  code: AngrConfigurationFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "python_missing":
    case "bridge_directory_missing":
    case "bridge_script_missing":
      return "executable_missing";
    case "python_not_executable":
    case "not_configured":
    case "not_absolute":
    case "jobs_invalid":
    case "timeout_invalid":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const angrConfigurationAvailability = (
  cause: AngrConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
