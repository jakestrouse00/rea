import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  LAB_VM_COMMAND_ENV,
  LAB_VM_COMMAND_REMEDIATION,
  LAB_VM_DEFAULT_COMMAND_TIMEOUT_MS,
  LAB_VM_MAX_OUTPUT_BYTES,
  LAB_VM_START_TIMEOUT_MS,
} from "../domain/vmlab/labVm.js";

/** One resolved lab-VM lane selection. */
export interface LabVmConfiguration {
  readonly command: string;
  readonly startTimeoutMs: number;
  readonly defaultCommandTimeoutMs: number;
  readonly maxOutputBytes: number;
}

export type LabVmFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable";

export class LabVmConfigurationFailure extends Error {
  readonly _tag = "LabVmConfigurationFailure";
  constructor(
    readonly code: LabVmFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "LabVmConfigurationFailure";
  }
}

const executabilityFailure = (
  command: string,
): LabVmConfigurationFailure | null => {
  try {
    accessSync(command, constants.X_OK);
    if (!statSync(command).isFile())
      return new LabVmConfigurationFailure(
        "binary_not_executable",
        `The selected limactl path is not a regular file: ${command}`,
        {
          setting: LAB_VM_COMMAND_ENV,
          selected_binary: command,
          remediation: LAB_VM_COMMAND_REMEDIATION,
        },
      );
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    const denied = code === "EACCES" || code === "EPERM";
    return new LabVmConfigurationFailure(
      denied ? "binary_not_executable" : "binary_missing",
      denied
        ? `Execution of the selected limactl binary was denied: ${command}`
        : `The selected limactl binary was not found: ${command}`,
      {
        setting: LAB_VM_COMMAND_ENV,
        selected_binary: command,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: LAB_VM_COMMAND_REMEDIATION,
      },
      { cause },
    );
  }
};

/** Resolve the caller-supplied limactl selection, fail-closed. */
export const resolveLabVmConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): LabVmConfiguration => {
  const command = environment[LAB_VM_COMMAND_ENV];
  if (command === undefined || command.trim() === "")
    throw new LabVmConfigurationFailure(
      "not_configured",
      `No limactl binary is selected: ${LAB_VM_COMMAND_ENV} is unset`,
      { setting: LAB_VM_COMMAND_ENV, remediation: LAB_VM_COMMAND_REMEDIATION },
    );
  if (!isAbsolute(command))
    throw new LabVmConfigurationFailure(
      "not_absolute",
      `${LAB_VM_COMMAND_ENV} must be an absolute path to the limactl binary`,
      {
        setting: LAB_VM_COMMAND_ENV,
        configured_path: command,
        remediation: LAB_VM_COMMAND_REMEDIATION,
      },
    );
  const failure = executabilityFailure(command);
  if (failure !== null) throw failure;
  return {
    command,
    startTimeoutMs: LAB_VM_START_TIMEOUT_MS,
    defaultCommandTimeoutMs: LAB_VM_DEFAULT_COMMAND_TIMEOUT_MS,
    maxOutputBytes: LAB_VM_MAX_OUTPUT_BYTES,
  };
};

const rejectionCodeOf = (code: LabVmFailureCode): ProviderRejectionCode => {
  switch (code) {
    case "binary_missing":
      return "executable_missing";
    case "binary_not_executable":
    case "not_configured":
    case "not_absolute":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const labVmConfigurationAvailability = (
  cause: LabVmConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
