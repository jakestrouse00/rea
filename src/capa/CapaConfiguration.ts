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
  CAPA_COMMAND_ENV,
  CAPA_COMMAND_REMEDIATION,
  CAPA_VERSION_PROBE_REMEDIATION,
} from "./CapaRelease.js";

const VERSION_TIMEOUT_MS = 10_000;
const VERSION_MAX_OUTPUT_BYTES = 64 * 1024;

/** One bounded capability match over a local executable. */
const DEFAULT_OPERATION_TIMEOUT_MS = 300_000;

/** Caller-selected capa CLI and REA-owned bounds. */
export interface CapaConfiguration {
  /** Caller-selected binary path, preserved exactly as configured. */
  readonly command: string;
  readonly operationTimeoutMs: number;
}

export type CapaConfigurationFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable"
  | "version_unresolved";

export class CapaConfigurationFailure extends Error {
  constructor(
    readonly code: CapaConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/**
 * Resolve the caller-supplied capa binary. This release has no PATH fallback:
 * an unset `REA_CAPA_COMMAND` is a configuration refusal, not an implicit
 * discovery.
 */
export const resolveCapaConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): CapaConfiguration => {
  const command = environment[CAPA_COMMAND_ENV];
  if (command === undefined || command.trim() === "")
    throw new CapaConfigurationFailure(
      "not_configured",
      `No capa CLI is selected: ${CAPA_COMMAND_ENV} is unset`,
      {
        setting: CAPA_COMMAND_ENV,
        remediation: CAPA_COMMAND_REMEDIATION,
      },
    );
  if (!isAbsolute(command))
    throw new CapaConfigurationFailure(
      "not_absolute",
      `${CAPA_COMMAND_ENV} must be an absolute path to the capa binary`,
      {
        setting: CAPA_COMMAND_ENV,
        configured_path: command,
        remediation: CAPA_COMMAND_REMEDIATION,
      },
    );
  return {
    command,
    operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS,
  };
};

const CAPA_VERSION_PATTERN = /\b(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b/u;

/** Parse `capa --version`, which prints a bare version line. */
export const parseCapaVersionOutput = (stdout: string): string | null => {
  const match = CAPA_VERSION_PATTERN.exec(stdout);
  return match === null ? null : match[1]!;
};

export interface CapaClientIdentity {
  readonly version: string | null;
}

/**
 * Probe the selected binary without reading any target. A capa version probe
 * loads capa's own rule engine and nothing about the analysis target.
 */
export const inspectCapaClient = async (
  configuration: CapaConfiguration,
  signal?: AbortSignal,
  operation = "analyze_binary_capabilities",
): Promise<CapaClientIdentity> => {
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
    const version = parseCapaVersionOutput(stdout);
    if (version === null)
      throw new CapaConfigurationFailure(
        "version_unresolved",
        "The selected capa binary exited successfully but did not report a recognizable version",
        {
          selected_binary: configuration.command,
          version_probe: "unrecognized_output",
          remediation: CAPA_VERSION_PROBE_REMEDIATION,
        },
      );
    return { version };
  } catch (cause) {
    if (cause instanceof CapaConfigurationFailure) throw cause;
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
        `capa version output exceeded the ${String(VERSION_MAX_OUTPUT_BYTES)}-byte capture budget`,
        { max_output_bytes: VERSION_MAX_OUTPUT_BYTES },
        {
          ...options,
          ...fixedAllowanceOptions(
            `The capa version-output capture allowance of ${String(VERSION_MAX_OUTPUT_BYTES)} bytes (this release has no runtime override)`,
            "capture",
          ),
        },
      );
    if (failure?.code === "ETIMEDOUT")
      throw new AnalysisTimeoutError(operation, VERSION_TIMEOUT_MS, {
        ...options,
        userMessage: `The capa version probe reached its ${String(VERSION_TIMEOUT_MS)} ms deadline (deadlineExpired). This release has no runtime override.`,
        remediationAction: `This ${String(VERSION_TIMEOUT_MS)} ms capa version probe has no runtime override. Allow execution, cleanup and delivery headroom in the outer MCP client deadline. Confirm outstanding work and cleanup before retrying.`,
      });
    if (failure?.code === "ENOENT")
      throw new CapaConfigurationFailure(
        "binary_missing",
        `The selected capa binary was not found: ${configuration.command}`,
        {
          selected_binary: configuration.command,
          remediation: CAPA_COMMAND_REMEDIATION,
        },
        { cause },
      );
    if (failure?.code === "EACCES" || failure?.code === "EPERM")
      throw new CapaConfigurationFailure(
        "binary_not_executable",
        `Execution of the selected capa binary was denied (${failure.code}): ${configuration.command}`,
        {
          selected_binary: configuration.command,
          filesystem_error: failure.code,
          remediation: CAPA_COMMAND_REMEDIATION,
        },
        { cause },
      );
    throw new CapaConfigurationFailure(
      "version_unresolved",
      "The selected capa binary did not report a usable version",
      {
        selected_binary: configuration.command,
        ...(failure === undefined
          ? {}
          : {
              exit_code: failure.code,
              stderr_excerpt: failure.stderr.slice(0, 512),
            }),
        remediation: CAPA_VERSION_PROBE_REMEDIATION,
      },
      { cause },
    );
  }
};

const rejectionCodeOf = (
  code: CapaConfigurationFailureCode,
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
export const capaConfigurationAvailability = (
  cause: CapaConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
