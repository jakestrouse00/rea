import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  PYCDC_COMMAND_ENV,
  PYLINGUAL_COMMAND_ENV,
  PYTHON_DECOMPILER_REMEDIATION,
} from "./PythonDecompilerRelease.js";

/** One bounded decompilation of a Python bytecode artifact. */
const DEFAULT_OPERATION_TIMEOUT_MS = 300_000;

export type PythonDecompilerTool = "pylingual" | "pycdc";

/** Caller-selected decompiler binary and REA-owned bounds. */
export interface PythonDecompilerConfiguration {
  readonly command: string;
  readonly tool: PythonDecompilerTool;
  readonly operationTimeoutMs: number;
}

export type PythonDecompilerFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable";

export class PythonDecompilerConfigurationFailure extends Error {
  constructor(
    readonly code: PythonDecompilerFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

const assertExecutable = (path: string): void => {
  accessSync(path, constants.X_OK);
};

/**
 * Resolve the caller-supplied Python decompiler. PyLingual wins when both
 * settings are present; an unset pair is a configuration refusal.
 */
export const resolvePythonDecompilerConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): PythonDecompilerConfiguration => {
  for (const [tool, setting] of [
    ["pylingual", PYLINGUAL_COMMAND_ENV],
    ["pycdc", PYCDC_COMMAND_ENV],
  ] as const) {
    const configured = environment[setting];
    if (configured === undefined || configured.trim() === "") continue;
    if (!isAbsolute(configured))
      throw new PythonDecompilerConfigurationFailure(
        "not_absolute",
        `${setting} must be an absolute path to the ${tool} binary`,
        {
          setting,
          configured_path: configured,
          remediation: PYTHON_DECOMPILER_REMEDIATION,
        },
      );
    try {
      assertExecutable(configured);
      if (!statSync(configured).isFile())
        throw new PythonDecompilerConfigurationFailure(
          "binary_not_executable",
          `The selected ${tool} path is not a regular file: ${configured}`,
          {
            setting,
            selected_binary: configured,
            remediation: PYTHON_DECOMPILER_REMEDIATION,
          },
        );
    } catch (cause: unknown) {
      if (cause instanceof PythonDecompilerConfigurationFailure) throw cause;
      const code = (cause as NodeJS.ErrnoException).code;
      throw new PythonDecompilerConfigurationFailure(
        code === "EACCES" || code === "EPERM"
          ? "binary_not_executable"
          : "binary_missing",
        code === "EACCES" || code === "EPERM"
          ? `Execution of the selected ${tool} binary was denied: ${configured}`
          : `The selected ${tool} binary was not found: ${configured}`,
        {
          setting,
          selected_binary: configured,
          ...(code === undefined ? {} : { filesystem_error: code }),
          remediation: PYTHON_DECOMPILER_REMEDIATION,
        },
        { cause },
      );
    }
    return {
      command: configured,
      tool,
      operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS,
    };
  }
  throw new PythonDecompilerConfigurationFailure(
    "not_configured",
    `No Python decompiler is selected: ${PYLINGUAL_COMMAND_ENV} and ${PYCDC_COMMAND_ENV} are unset`,
    {
      settings: [PYLINGUAL_COMMAND_ENV, PYCDC_COMMAND_ENV],
      remediation: PYTHON_DECOMPILER_REMEDIATION,
    },
  );
};

const rejectionCodeOf = (
  code: PythonDecompilerFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "binary_missing":
      return "executable_missing";
    case "binary_not_executable":
      return "not_configured";
    case "not_configured":
    case "not_absolute":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const pythonDecompilerConfigurationAvailability = (
  cause: PythonDecompilerConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
