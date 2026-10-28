import { accessSync, constants, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import { err, ok, type Result } from "../domain/result.js";
import {
  LIEF_BRIDGE_DIR_ENV,
  LIEF_BRIDGE_DIR_REMEDIATION,
  LIEF_BRIDGE_FILE_NAME,
  LIEF_COMMAND_ENV,
  LIEF_COMMAND_REMEDIATION,
  LIEF_LIMITS,
  LIEF_PROTOCOL_VERSION,
} from "../domain/lief/liefLimits.js";

/** Caller-selected interpreter and bridge script, with the fixed run policy. */
export interface LiefConfiguration {
  /** Caller-selected interpreter path, preserved exactly as configured. */
  readonly command: string;
  readonly bridgeDirectory: string;
  readonly bridgePath: string;
  readonly deadlineMs: number;
  readonly protocolVersion: number;
}

/** Why the configured environment cannot select a usable LIEF bridge. */
export interface LiefConfigurationFailure {
  readonly code:
    | "not_configured"
    | "not_absolute"
    | "command_missing"
    | "command_not_executable"
    | "bridge_directory_missing"
    | "bridge_script_not_found";
  readonly reason: string;
  readonly setting: string;
  /** The caller's exact fix for this failure. */
  readonly remediation: string;
}

const failure = (
  code: LiefConfigurationFailure["code"],
  setting: string,
  reason: string,
  remediation: string,
): Result<never, LiefConfigurationFailure> =>
  err({ code, reason, setting, remediation });

/** Parse the LIEF settings without touching the filesystem or any process. */
export const readLiefConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv>,
): Result<LiefConfiguration, LiefConfigurationFailure> => {
  const command = environment[LIEF_COMMAND_ENV];
  if (command === undefined || command.trim() === "")
    return failure(
      "not_configured",
      LIEF_COMMAND_ENV,
      `${LIEF_COMMAND_ENV} is not set.`,
      LIEF_COMMAND_REMEDIATION,
    );
  if (!isAbsolute(command))
    return failure(
      "not_absolute",
      LIEF_COMMAND_ENV,
      `${LIEF_COMMAND_ENV} must be an absolute path; received ${command}.`,
      LIEF_COMMAND_REMEDIATION,
    );
  const directory = environment[LIEF_BRIDGE_DIR_ENV];
  if (directory === undefined || directory.trim() === "")
    return failure(
      "not_configured",
      LIEF_BRIDGE_DIR_ENV,
      `${LIEF_BRIDGE_DIR_ENV} is not set.`,
      LIEF_BRIDGE_DIR_REMEDIATION,
    );
  if (!isAbsolute(directory))
    return failure(
      "not_absolute",
      LIEF_BRIDGE_DIR_ENV,
      `${LIEF_BRIDGE_DIR_ENV} must be an absolute path; received ${directory}.`,
      LIEF_BRIDGE_DIR_REMEDIATION,
    );
  return ok({
    command,
    bridgeDirectory: directory,
    bridgePath: join(directory, LIEF_BRIDGE_FILE_NAME),
    deadlineMs: LIEF_LIMITS.defaultDeadlineMs,
    protocolVersion: LIEF_PROTOCOL_VERSION,
  });
};

const executableFailure = (
  command: string,
): LiefConfigurationFailure | null => {
  try {
    if (!statSync(command).isFile())
      return {
        code: "command_not_executable",
        setting: LIEF_COMMAND_ENV,
        reason: `${LIEF_COMMAND_ENV} is not a regular file: ${command}.`,
        remediation: LIEF_COMMAND_REMEDIATION,
      };
    accessSync(command, constants.X_OK);
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === "EACCES" || code === "EPERM")
      return {
        code: "command_not_executable",
        setting: LIEF_COMMAND_ENV,
        reason: `Execution of the selected interpreter was denied: ${command}.`,
        remediation: LIEF_COMMAND_REMEDIATION,
      };
    return {
      code: "command_missing",
      setting: LIEF_COMMAND_ENV,
      reason: `The selected interpreter was not found: ${command}.`,
      remediation: LIEF_COMMAND_REMEDIATION,
    };
  }
};

const bridgeFailure = (directory: string): LiefConfigurationFailure | null => {
  try {
    if (!statSync(directory).isDirectory())
      return {
        code: "bridge_directory_missing",
        setting: LIEF_BRIDGE_DIR_ENV,
        reason: `${LIEF_BRIDGE_DIR_ENV} is not a directory: ${directory}.`,
        remediation: LIEF_BRIDGE_DIR_REMEDIATION,
      };
  } catch {
    return {
      code: "bridge_directory_missing",
      setting: LIEF_BRIDGE_DIR_ENV,
      reason: `The selected bridge directory was not found: ${directory}.`,
      remediation: LIEF_BRIDGE_DIR_REMEDIATION,
    };
  }
  const bridgePath = join(directory, LIEF_BRIDGE_FILE_NAME);
  try {
    if (!statSync(bridgePath).isFile())
      return {
        code: "bridge_script_not_found",
        setting: LIEF_BRIDGE_DIR_ENV,
        reason: `${LIEF_BRIDGE_FILE_NAME} is not a regular file: ${bridgePath}.`,
        remediation: LIEF_BRIDGE_DIR_REMEDIATION,
      };
    accessSync(bridgePath, constants.R_OK);
    return null;
  } catch {
    return {
      code: "bridge_script_not_found",
      setting: LIEF_BRIDGE_DIR_ENV,
      reason: `${LIEF_BRIDGE_FILE_NAME} could not be read in ${directory}.`,
      remediation: LIEF_BRIDGE_DIR_REMEDIATION,
    };
  }
};

/** Resolve the caller's interpreter and bridge script, fail-closed on any gap. */
export const resolveLiefConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv>,
): Result<LiefConfiguration, LiefConfigurationFailure> => {
  const parsed = readLiefConfiguration(environment);
  if (!parsed.ok) return parsed;
  const commandProblem = executableFailure(parsed.value.command);
  if (commandProblem !== null) return err(commandProblem);
  const bridgeProblem = bridgeFailure(parsed.value.bridgeDirectory);
  if (bridgeProblem !== null) return err(bridgeProblem);
  return parsed;
};
