import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

import type { ProviderAvailability } from "../../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../../contracts/providerSelection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  DEFAULT_VIEW8_OPERATION_TIMEOUT_MS,
  VIEW8_COMMAND_ENV,
  VIEW8_REMEDIATION,
} from "./View8Release.js";

/** Caller-selected View8 launcher and REA-owned bounds. */
export interface View8Configuration {
  readonly command: string;
  readonly operationTimeoutMs: number;
}

export type View8FailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable";

export class View8ConfigurationFailure extends Error {
  constructor(
    readonly code: View8FailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

const failure = (
  code: View8FailureCode,
  message: string,
  diagnostics: Readonly<Record<string, JsonValue>>,
  cause?: unknown,
): View8ConfigurationFailure =>
  new View8ConfigurationFailure(
    code,
    message,
    {
      setting: VIEW8_COMMAND_ENV,
      remediation: VIEW8_REMEDIATION,
      ...diagnostics,
    },
    cause === undefined ? undefined : { cause },
  );

/**
 * Resolve the caller-supplied View8 launcher. An unset, relative or unusable
 * selection is a configuration refusal; REA never searches PATH or installs.
 */
export const resolveView8Configuration = (
  environment: Readonly<Record<string, string | undefined>>,
): View8Configuration => {
  const configured = environment[VIEW8_COMMAND_ENV];
  if (configured === undefined || configured.trim() === "")
    throw failure(
      "not_configured",
      `No View8 launcher is selected: ${VIEW8_COMMAND_ENV} is unset`,
      {},
    );
  if (!isAbsolute(configured))
    throw failure(
      "not_absolute",
      `${VIEW8_COMMAND_ENV} must be an absolute path to the View8 launcher`,
      { configured_path: configured },
    );
  try {
    accessSync(configured, constants.X_OK);
    if (!statSync(configured).isFile())
      throw failure(
        "binary_not_executable",
        `The selected View8 launcher is not a regular file: ${configured}`,
        { selected_binary: configured },
      );
  } catch (cause: unknown) {
    if (cause instanceof View8ConfigurationFailure) throw cause;
    const code = (cause as NodeJS.ErrnoException).code;
    throw failure(
      code === "EACCES" || code === "EPERM"
        ? "binary_not_executable"
        : "binary_missing",
      code === "EACCES" || code === "EPERM"
        ? `Execution of the selected View8 launcher was denied: ${configured}`
        : `The selected View8 launcher was not found: ${configured}`,
      {
        selected_binary: configured,
        ...(code === undefined ? {} : { filesystem_error: code }),
      },
      cause,
    );
  }
  return {
    command: configured,
    operationTimeoutMs: DEFAULT_VIEW8_OPERATION_TIMEOUT_MS,
  };
};

const rejectionCodeOf = (code: View8FailureCode): ProviderRejectionCode => {
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
export const view8ConfigurationAvailability = (
  cause: View8ConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
