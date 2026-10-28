import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  BINDIFF_COMMAND_ENV,
  BINDIFF_COMMAND_REMEDIATION,
  BINEXPORT_COMMAND_ENV,
  BINEXPORT_COMMAND_REMEDIATION,
} from "./BindiffRelease.js";

/** One bounded binary comparison. */
const DIFF_TIMEOUT_MS = 600_000;
/** One bounded BinExport export. */
const EXPORT_TIMEOUT_MS = 600_000;

export interface BinDiffCommandConfiguration {
  readonly command: string;
  readonly operationTimeoutMs: number;
}

export type BinDiffFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable";

export class BinDiffConfigurationFailure extends Error {
  constructor(
    readonly code: BinDiffFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

const executabilityFailure = (
  setting: string,
  name: string,
  command: string,
  remediation: string,
): BinDiffConfigurationFailure | null => {
  try {
    accessSync(command, constants.X_OK);
    if (!statSync(command).isFile())
      return new BinDiffConfigurationFailure(
        "binary_not_executable",
        `The selected ${name} path is not a regular file: ${command}`,
        { setting, selected_binary: command, remediation },
      );
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    return new BinDiffConfigurationFailure(
      code === "EACCES" || code === "EPERM"
        ? "binary_not_executable"
        : "binary_missing",
      code === "EACCES" || code === "EPERM"
        ? `Execution of the selected ${name} binary was denied: ${command}`
        : `The selected ${name} binary was not found: ${command}`,
      {
        setting,
        selected_binary: command,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation,
      },
      { cause },
    );
  }
};

const resolveCommand = (
  environment: Readonly<Record<string, string | undefined>>,
  setting: string,
  name: string,
  remediation: string,
): string => {
  const command = environment[setting];
  if (command === undefined || command.trim() === "")
    throw new BinDiffConfigurationFailure(
      "not_configured",
      `No ${name} binary is selected: ${setting} is unset`,
      { setting, remediation },
    );
  if (!isAbsolute(command))
    throw new BinDiffConfigurationFailure(
      "not_absolute",
      `${setting} must be an absolute path to the ${name} binary`,
      { setting, configured_path: command, remediation },
    );
  const failure = executabilityFailure(setting, name, command, remediation);
  if (failure !== null) throw failure;
  return command;
};

/** Resolve the caller-supplied BinDiff adapter command. */
export const resolveBindiffConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): BinDiffCommandConfiguration => ({
  command: resolveCommand(
    environment,
    BINDIFF_COMMAND_ENV,
    "BinDiff",
    BINDIFF_COMMAND_REMEDIATION,
  ),
  operationTimeoutMs: DIFF_TIMEOUT_MS,
});

/** Resolve the caller-supplied BinExport exporter command. */
export const resolveBinexportConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): BinDiffCommandConfiguration => ({
  command: resolveCommand(
    environment,
    BINEXPORT_COMMAND_ENV,
    "BinExport exporter",
    BINEXPORT_COMMAND_REMEDIATION,
  ),
  operationTimeoutMs: EXPORT_TIMEOUT_MS,
});

const rejectionCodeOf = (code: BinDiffFailureCode): ProviderRejectionCode => {
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
export const bindiffConfigurationAvailability = (
  cause: BinDiffConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
