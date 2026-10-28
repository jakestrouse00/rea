import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import {
  ExecFileOutputCancelledError,
  execFileOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import {
  ANDROGUARD_BRIDGE_DIR_ENV,
  ANDROGUARD_PYTHON_ENV,
  ANDROGUARD_PYTHON_REMEDIATION,
  ILEAPP_COMMAND_ENV,
  ILEAPP_COMMAND_REMEDIATION,
  OBJECTION_COMMAND_ENV,
  OBJECTION_COMMAND_REMEDIATION,
} from "./MobileToolchainRelease.js";

const bundledBridgeDirectory = fileURLToPath(
  new URL("../../bridge/mobile", import.meta.url),
);

/** Why a mobile lane's selected tool cannot be used. */
export class MobileConfigurationFailure extends Error {
  constructor(
    readonly code:
      | "not_configured"
      | "not_absolute"
      | "binary_missing"
      | "binary_not_executable"
      | "bridge_missing",
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "MobileConfigurationFailure";
  }
}

export interface ObjectionConfiguration {
  readonly command: string;
}

export interface AndroguardConfiguration {
  readonly python: string;
  readonly bridgeScript: string;
  readonly bridgeDirectory: string;
}

export interface IleappConfiguration {
  readonly command: string;
}

const requireAbsoluteSetting = (
  environment: Readonly<Record<string, string | undefined>>,
  setting: string,
  remediation: string,
  what: string,
): string => {
  const value = environment[setting];
  if (value === undefined || value.trim() === "")
    throw new MobileConfigurationFailure(
      "not_configured",
      `No ${what} is selected: ${setting} is unset`,
      { setting, remediation },
    );
  if (!isAbsolute(value))
    throw new MobileConfigurationFailure(
      "not_absolute",
      `${setting} must be an absolute path to the ${what}`,
      { setting, configured_path: value, remediation },
    );
  return value;
};

/** Resolve the caller-supplied objection launcher. */
export const resolveObjectionConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): ObjectionConfiguration => ({
  command: requireAbsoluteSetting(
    environment,
    OBJECTION_COMMAND_ENV,
    OBJECTION_COMMAND_REMEDIATION,
    "objection launcher",
  ),
});

/** Resolve the caller-supplied androguard interpreter and the bridge to run. */
export const resolveAndroguardConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): AndroguardConfiguration => {
  const python = requireAbsoluteSetting(
    environment,
    ANDROGUARD_PYTHON_ENV,
    ANDROGUARD_PYTHON_REMEDIATION,
    "Python interpreter with androguard",
  );
  const configuredDirectory = environment[ANDROGUARD_BRIDGE_DIR_ENV];
  const bridgeDirectory =
    configuredDirectory === undefined || configuredDirectory.trim() === ""
      ? bundledBridgeDirectory
      : configuredDirectory;
  if (!isAbsolute(bridgeDirectory))
    throw new MobileConfigurationFailure(
      "not_absolute",
      `${ANDROGUARD_BRIDGE_DIR_ENV} must be an absolute directory path`,
      {
        setting: ANDROGUARD_BRIDGE_DIR_ENV,
        configured_path: bridgeDirectory,
        remediation: ANDROGUARD_PYTHON_REMEDIATION,
      },
    );
  return {
    python,
    bridgeDirectory,
    bridgeScript: join(bridgeDirectory, "androguard_bridge.py"),
  };
};

/** Resolve the caller-supplied iLEAPP/ALEAPP launcher. */
export const resolveIleappConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): IleappConfiguration => ({
  command: requireAbsoluteSetting(
    environment,
    ILEAPP_COMMAND_ENV,
    ILEAPP_COMMAND_REMEDIATION,
    "iLEAPP or ALEAPP launcher",
  ),
});

const rejectionCodeOf = (
  code: MobileConfigurationFailure["code"],
): ProviderRejectionCode => {
  switch (code) {
    case "binary_missing":
    case "bridge_missing":
      return "executable_missing";
    case "not_configured":
    case "not_absolute":
    case "binary_not_executable":
      return "not_configured";
  }
};

export const mobileConfigurationAvailability = (
  cause: MobileConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});

/** One bounded child run's observed outcome, without failure policy. */
export interface MobileCommandRun {
  readonly stdout: string;
  readonly stderr: string;
  readonly exit_code: number | null;
  readonly timed_out: boolean;
  readonly output_truncated: boolean;
}

export type MobileCommandRunner = (request: {
  readonly command: string;
  readonly arguments: readonly string[];
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly signal?: AbortSignal | undefined;
}) => Promise<MobileCommandRun>;

/**
 * Run one child with a bounded deadline and capture budget. A missing or
 * non-executable launcher and a non-zero exit are observed outcomes the
 * caller classifies; only cancellation becomes an error here.
 */
export const runMobileCommand: MobileCommandRunner = async (request) => {
  try {
    const { stdout, stderr } = await execFileOutput(
      request.command,
      [...request.arguments],
      {
        timeout: request.timeoutMs,
        stopSignal: "SIGTERM",
        maxBuffer: request.maxOutputBytes,
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      },
    );
    return {
      stdout,
      stderr,
      exit_code: 0,
      timed_out: false,
      output_truncated: false,
    };
  } catch (cause: unknown) {
    if (cause instanceof ExecFileOutputCancelledError)
      throw new AnalysisCancelledError("run_mobile_tool", {
        cause: cause.cause,
      });
    const failure = execFileOutputFailure(cause);
    if (failure === undefined) throw cause;
    return {
      stdout: failure.stdout,
      stderr: failure.stderr,
      exit_code: typeof failure.code === "number" ? failure.code : null,
      timed_out: failure.code === "ETIMEDOUT",
      output_truncated: failure.outputTruncated,
    };
  }
};

/** Classify a child launch failure into the lane's typed errors. */
export const mobileCommandError = (
  operation: string,
  command: string,
  run: MobileCommandRun,
  timeoutMs: number,
): AnalysisError | undefined => {
  if (run.timed_out)
    return new AnalysisTimeoutError(operation, timeoutMs, {
      userMessage: `The selected mobile tool did not finish within ${String(timeoutMs)} ms and was stopped. Reduce the selected artifact or raise the per-call timeout_ms.`,
    });
  if (run.output_truncated)
    return new AnalysisResourceConstraintError(
      operation,
      "memory",
      "The selected mobile tool exceeded its capture budget; its output was refused rather than truncated and parsed",
      null,
      { retryable: false },
    );
  return undefined;
};
