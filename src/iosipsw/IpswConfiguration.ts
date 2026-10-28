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
  IPSW_COMMAND_ENV,
  IPSW_COMMAND_REMEDIATION,
  IPSW_DSC_PATH_ENV,
  IPSW_DSC_PATH_REMEDIATION,
  IPSW_VERSION_PROBE_REMEDIATION,
} from "./IpswRelease.js";

const VERSION_TIMEOUT_MS = 10_000;
const VERSION_MAX_OUTPUT_BYTES = 64 * 1024;

/** One bounded ipsw inspection command. */
const DEFAULT_OPERATION_TIMEOUT_MS = 120_000;

/** Shared-cache extraction writes many files and gets a wider deadline. */
const EXTRACTION_TIMEOUT_MS = 600_000;

/** Caller-selected ipsw CLI and REA-owned bounds. */
export interface IpswConfiguration {
  /** Caller-selected binary path, preserved exactly as configured. */
  readonly command: string;
  /** Configured shared-cache file or directory; null when unset. */
  readonly dscPath: string | null;
  readonly operationTimeoutMs: number;
  readonly extractionTimeoutMs: number;
}

export type IpswConfigurationFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable"
  | "version_unresolved"
  | "dsc_path_invalid";

export class IpswConfigurationFailure extends Error {
  constructor(
    readonly code: IpswConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/**
 * Resolve the caller-supplied ipsw binary and optional shared-cache location.
 * This release has no PATH fallback: an unset `REA_IPSW_COMMAND` is a
 * configuration refusal, not an implicit discovery.
 */
export const resolveIpswConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): IpswConfiguration => {
  const command = environment[IPSW_COMMAND_ENV];
  if (command === undefined || command.trim() === "")
    throw new IpswConfigurationFailure(
      "not_configured",
      `No ipsw CLI is selected: ${IPSW_COMMAND_ENV} is unset`,
      {
        setting: IPSW_COMMAND_ENV,
        remediation: IPSW_COMMAND_REMEDIATION,
      },
    );
  if (!isAbsolute(command))
    throw new IpswConfigurationFailure(
      "not_absolute",
      `${IPSW_COMMAND_ENV} must be an absolute path to the ipsw binary`,
      {
        setting: IPSW_COMMAND_ENV,
        configured_path: command,
        remediation: IPSW_COMMAND_REMEDIATION,
      },
    );
  const configuredDsc = environment[IPSW_DSC_PATH_ENV];
  const dscPath =
    configuredDsc === undefined || configuredDsc.trim() === ""
      ? null
      : configuredDsc;
  if (dscPath !== null && !isAbsolute(dscPath))
    throw new IpswConfigurationFailure(
      "dsc_path_invalid",
      `${IPSW_DSC_PATH_ENV} must be an absolute path to a dyld shared cache file or directory`,
      {
        setting: IPSW_DSC_PATH_ENV,
        configured_path: dscPath,
        remediation: IPSW_DSC_PATH_REMEDIATION,
      },
    );
  return {
    command,
    dscPath,
    operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS,
    extractionTimeoutMs: EXTRACTION_TIMEOUT_MS,
  };
};

const IPSW_VERSION_PATTERN = /\b(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b/u;

/** Parse `ipsw version`, which prints a bare or `ipsw version <v>` line. */
export const parseIpswVersionOutput = (stdout: string): string | null => {
  const match = IPSW_VERSION_PATTERN.exec(stdout);
  return match === null ? null : match[1]!;
};

export interface IpswClientIdentity {
  readonly version: string | null;
}

/**
 * Probe the selected binary without reading any archive. `ipsw version`
 * reports the build and nothing about the target.
 */
export const inspectIpswClient = async (
  configuration: IpswConfiguration,
  signal?: AbortSignal,
  operation = "inspect_ipsw",
): Promise<IpswClientIdentity> => {
  try {
    const { stdout } = await execFileOutput(
      configuration.command,
      ["version"],
      {
        timeout: VERSION_TIMEOUT_MS,
        stopSignal: "SIGTERM",
        maxBuffer: VERSION_MAX_OUTPUT_BYTES,
        ...(signal === undefined ? {} : { signal }),
      },
    );
    const version = parseIpswVersionOutput(stdout);
    if (version === null)
      throw new IpswConfigurationFailure(
        "version_unresolved",
        "The selected ipsw binary exited successfully but did not report a recognizable version",
        {
          selected_binary: configuration.command,
          version_probe: "unrecognized_output",
          remediation: IPSW_VERSION_PROBE_REMEDIATION,
        },
      );
    return { version };
  } catch (cause) {
    if (cause instanceof IpswConfigurationFailure) throw cause;
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
        `ipsw version output exceeded the ${String(VERSION_MAX_OUTPUT_BYTES)}-byte capture budget`,
        { max_output_bytes: VERSION_MAX_OUTPUT_BYTES },
        {
          ...options,
          ...fixedAllowanceOptions(
            `The ipsw version-output capture allowance of ${String(VERSION_MAX_OUTPUT_BYTES)} bytes (this release has no runtime override)`,
            "capture",
          ),
        },
      );
    if (failure?.code === "ETIMEDOUT")
      throw new AnalysisTimeoutError(operation, VERSION_TIMEOUT_MS, {
        ...options,
        userMessage: `The ipsw version probe reached its ${String(VERSION_TIMEOUT_MS)} ms deadline (deadlineExpired). This release has no runtime override.`,
        remediationAction: `This ${String(VERSION_TIMEOUT_MS)} ms ipsw version probe has no runtime override. Allow execution, cleanup and delivery headroom in the outer MCP client deadline. Confirm outstanding work and cleanup before retrying.`,
      });
    if (failure?.code === "ENOENT")
      throw new IpswConfigurationFailure(
        "binary_missing",
        `The selected ipsw binary was not found: ${configuration.command}`,
        {
          selected_binary: configuration.command,
          remediation: IPSW_COMMAND_REMEDIATION,
        },
        { cause },
      );
    if (failure?.code === "EACCES" || failure?.code === "EPERM")
      throw new IpswConfigurationFailure(
        "binary_not_executable",
        `Execution of the selected ipsw binary was denied (${failure.code}): ${configuration.command}`,
        {
          selected_binary: configuration.command,
          filesystem_error: failure.code,
          remediation: IPSW_COMMAND_REMEDIATION,
        },
        { cause },
      );
    throw new IpswConfigurationFailure(
      "version_unresolved",
      "The selected ipsw binary did not report a usable version",
      {
        selected_binary: configuration.command,
        ...(failure === undefined
          ? {}
          : {
              exit_code: failure.code,
              stderr_excerpt: failure.stderr.slice(0, 512),
            }),
        remediation: IPSW_VERSION_PROBE_REMEDIATION,
      },
      { cause },
    );
  }
};

const rejectionCodeOf = (
  code: IpswConfigurationFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "binary_missing":
      return "executable_missing";
    case "version_unresolved":
      return "version_unresolved";
    case "not_configured":
    case "not_absolute":
    case "binary_not_executable":
    case "dsc_path_invalid":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const ipswConfigurationAvailability = (
  cause: IpswConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
