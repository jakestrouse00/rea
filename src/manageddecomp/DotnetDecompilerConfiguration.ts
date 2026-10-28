import { isAbsolute } from "node:path";

import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
import {
  ExecFileOutputCancelledError,
  execFileFailureCapturedOutput,
  execFileOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import {
  ILSPY_COMMAND_ENV,
  ILSPY_COMMAND_REMEDIATION,
  ILSPY_VERSION_PROBE_REMEDIATION,
} from "./DotnetDecompilerRelease.js";

const VERSION_TIMEOUT_MS = 10_000;
const VERSION_MAX_OUTPUT_BYTES = 64 * 1024;

/** One bounded decompilation of an assembly. */
const DEFAULT_OPERATION_TIMEOUT_MS = 300_000;

/** Caller-selected ilspycmd binary and REA-owned bounds. */
export interface DotnetDecompilerConfiguration {
  readonly command: string;
  readonly operationTimeoutMs: number;
}

export type DotnetDecompilerFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable"
  | "version_unresolved";

export class DotnetDecompilerConfigurationFailure extends Error {
  constructor(
    readonly code: DotnetDecompilerFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/**
 * Resolve the caller-supplied ilspycmd binary from the existing
 * `REA_ILSPY_CMD_PATH` setting. This lane formalizes that setting rather than
 * adding a second one; an unset value is a configuration refusal.
 */
export const resolveDotnetDecompilerConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): DotnetDecompilerConfiguration => {
  const command = environment[ILSPY_COMMAND_ENV];
  if (command === undefined || command.trim() === "")
    throw new DotnetDecompilerConfigurationFailure(
      "not_configured",
      `No ilspycmd binary is selected: ${ILSPY_COMMAND_ENV} is unset`,
      {
        setting: ILSPY_COMMAND_ENV,
        remediation: ILSPY_COMMAND_REMEDIATION,
      },
    );
  if (!isAbsolute(command))
    throw new DotnetDecompilerConfigurationFailure(
      "not_absolute",
      `${ILSPY_COMMAND_ENV} must be an absolute path to the ilspycmd binary`,
      {
        setting: ILSPY_COMMAND_ENV,
        configured_path: command,
        remediation: ILSPY_COMMAND_REMEDIATION,
      },
    );
  return {
    command,
    operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS,
  };
};

const ILSPY_VERSION_PATTERN =
  /(?:^|\s)(\d+\.\d+\.\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?)\s*$/mu;

/** Parse `ilspycmd --version`, which prints `ilspycmd: <version>` or a bare version. */
export const parseIlspyVersionOutput = (stdout: string): string | null => {
  const match = ILSPY_VERSION_PATTERN.exec(stdout.trim());
  return match === null ? null : match[1]!;
};

export interface DotnetDecompilerClientIdentity {
  readonly version: string | null;
}

/** Probe the selected binary without reading an assembly. */
export const inspectDotnetDecompilerClient = async (
  configuration: DotnetDecompilerConfiguration,
  signal?: AbortSignal,
  operation = "decompile_dotnet_assembly",
): Promise<DotnetDecompilerClientIdentity> => {
  try {
    const { stdout } = await execFileOutput(
      configuration.command,
      ["--version"],
      {
        timeout: VERSION_TIMEOUT_MS,
        stopSignal: "SIGTERM",
        maxBuffer: VERSION_MAX_OUTPUT_BYTES,
        ...(signal === undefined ? {} : { signal }),
      },
    );
    const version = parseIlspyVersionOutput(stdout);
    if (version === null)
      throw new DotnetDecompilerConfigurationFailure(
        "version_unresolved",
        "The selected ilspycmd binary exited successfully but did not report a recognizable version",
        {
          selected_binary: configuration.command,
          version_probe: "unrecognized_output",
          remediation: ILSPY_VERSION_PROBE_REMEDIATION,
        },
      );
    return { version };
  } catch (cause) {
    if (cause instanceof DotnetDecompilerConfigurationFailure) throw cause;
    const failure = execFileOutputFailure(cause);
    if (cause instanceof ExecFileOutputCancelledError)
      throw new AnalysisCancelledError(operation, {
        cause: cause.cause,
        ...(failure === undefined
          ? {}
          : { capturedOutput: execFileFailureCapturedOutput(failure) }),
      });
    const diagnostics = {
      selected_binary: configuration.command,
      ...(failure === undefined ? {} : { exit_code: failure.code }),
    };
    const options = {
      cause,
      diagnostics,
      ...(failure === undefined
        ? {}
        : { capturedOutput: execFileFailureCapturedOutput(failure) }),
    };
    if (failure?.outputTruncated === true)
      throw new AnalysisResourceConstraintError(
        operation,
        "memory",
        `ilspycmd version output exceeded the ${String(VERSION_MAX_OUTPUT_BYTES)}-byte capture budget`,
        { max_output_bytes: VERSION_MAX_OUTPUT_BYTES },
        {
          ...options,
          ...fixedAllowanceOptions(
            `The ilspycmd version-output capture allowance of ${String(VERSION_MAX_OUTPUT_BYTES)} bytes (this release has no runtime override)`,
            "capture",
          ),
        },
      );
    if (failure?.code === "ETIMEDOUT")
      throw new AnalysisTimeoutError(operation, VERSION_TIMEOUT_MS, {
        ...options,
        userMessage: `The ilspycmd version probe reached its ${String(VERSION_TIMEOUT_MS)} ms deadline (deadlineExpired). This release has no runtime override.`,
        remediationAction: `This ${String(VERSION_TIMEOUT_MS)} ms ilspycmd version probe has no runtime override. Allow execution, cleanup and delivery headroom in the outer MCP client deadline. Confirm outstanding work and cleanup before retrying.`,
      });
    if (failure?.code === "ENOENT")
      throw new DotnetDecompilerConfigurationFailure(
        "binary_missing",
        `The selected ilspycmd binary was not found: ${configuration.command}`,
        {
          selected_binary: configuration.command,
          remediation: ILSPY_COMMAND_REMEDIATION,
        },
        { cause },
      );
    if (failure?.code === "EACCES" || failure?.code === "EPERM")
      throw new DotnetDecompilerConfigurationFailure(
        "binary_not_executable",
        `Execution of the selected ilspycmd binary was denied (${failure.code}): ${configuration.command}`,
        {
          selected_binary: configuration.command,
          filesystem_error: failure.code,
          remediation: ILSPY_COMMAND_REMEDIATION,
        },
        { cause },
      );
    throw new DotnetDecompilerConfigurationFailure(
      "version_unresolved",
      "The selected ilspycmd binary did not report a usable version",
      {
        selected_binary: configuration.command,
        ...(failure === undefined
          ? {}
          : {
              exit_code: failure.code,
              stderr_excerpt: failure.stderr.slice(0, 512),
            }),
        remediation: ILSPY_VERSION_PROBE_REMEDIATION,
      },
      { cause },
    );
  }
};

const rejectionCodeOf = (
  code: DotnetDecompilerFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "binary_missing":
      return "executable_missing";
    case "version_unresolved":
      return "version_unresolved";
    case "not_configured":
    case "not_absolute":
    case "binary_not_executable":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const dotnetDecompilerConfigurationAvailability = (
  cause: DotnetDecompilerConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
