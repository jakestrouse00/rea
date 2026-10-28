import { access, stat } from "node:fs/promises";
import { constants } from "node:fs";
import { isAbsolute, join } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import { SANDBOX_PROFILE_EXECUTABLE } from "../domain/sandboxProfiles.js";
import {
  parseProtolearnLabEndpoints,
  ProtolearnConfigurationFailure,
  type LabEndpoint,
} from "../domain/protolearn/labEndpoints.js";
import {
  PROTOLEARN_BRIDGE_DIR_ENV,
  PROTOLEARN_BRIDGE_DIR_REMEDIATION,
  PROTOLEARN_BRIDGE_FILE_NAME,
  PROTOLEARN_LAB_ENDPOINTS_ENV,
  PROTOLEARN_LAB_ENDPOINTS_REMEDIATION,
  PROTOLEARN_LIMITS,
  PROTOLEARN_PROBE_TIMEOUT_ENV,
  PROTOLEARN_PROBE_TIMEOUT_SETTING,
  PROTOLEARN_PYTHON_ENV,
  PROTOLEARN_PYTHON_ENV_REMEDIATION,
} from "../domain/protolearn/protolearnLimits.js";

export type ProtolearnProbeConfigurationFailureCode =
  | "unsupported_host"
  | "probe_python_not_configured"
  | "bridge_dir_not_configured"
  | "not_absolute"
  | "interpreter_missing"
  | "bridge_missing"
  | "invalid_timeout"
  | "lab_endpoints_not_configured"
  | "lab_endpoints_invalid";

/** A probe-lane selection refusal the provider reports as a configuration answer. */
export class ProtolearnProbeConfigurationFailure extends Error {
  constructor(
    readonly code: ProtolearnProbeConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, string | number | null>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ProtolearnProbeConfigurationFailure";
  }
}

/** Everything one probe run needs, resolved before any socket opens. */
export interface ProtolearnProbeConfiguration {
  readonly python: string;
  readonly bridgeScript: string;
  readonly endpoints: readonly LabEndpoint[];
  readonly probeTimeoutMs: number;
}

/** Whether this host can confine a probe child with the deny-default profile. */
export const protolearnSandboxHostSupported = (
  platform: string = process.platform,
): boolean => platform === "darwin";

const sandboxUnsupported = (platform: string): ProtolearnProbeConfigurationFailure =>
  new ProtolearnProbeConfigurationFailure(
    "unsupported_host",
    `The learned-model probe lane confines its child with ${SANDBOX_PROFILE_EXECUTABLE}, which this host (${platform}) does not provide. No active probe runs unconfined.`,
    { platform },
  );

const requiredAbsolute = (
  value: string | undefined,
  code: ProtolearnProbeConfigurationFailureCode,
  setting: string,
  remediation: string,
): string => {
  if (value === undefined || value.trim() === "")
    throw new ProtolearnProbeConfigurationFailure(
      code,
      `${setting} is not set, so the learned-model probe lane is disabled`,
      { setting, remediation },
    );
  if (!isAbsolute(value))
    throw new ProtolearnProbeConfigurationFailure(
      "not_absolute",
      `${setting} must be an absolute path`,
      { setting, configured: value, remediation },
    );
  return value;
};

const probeTimeout = (
  environment: Readonly<Record<string, string | undefined>>,
  settingMs: number | undefined,
): number => {
  if (settingMs !== undefined) return settingMs;
  const configured = environment[PROTOLEARN_PROBE_TIMEOUT_ENV];
  if (configured === undefined || configured.trim() === "")
    return PROTOLEARN_LIMITS.defaultProbeTimeoutMs;
  if (!/^[1-9][0-9]{0,6}$/u.test(configured.trim()))
    throw new ProtolearnProbeConfigurationFailure(
      "invalid_timeout",
      `${PROTOLEARN_PROBE_TIMEOUT_ENV} must be a positive integer number of milliseconds`,
      {
        setting: PROTOLEARN_PROBE_TIMEOUT_ENV,
        configured,
        remediation: `Set ${PROTOLEARN_PROBE_TIMEOUT_ENV} to a whole number of milliseconds between 1 and ${String(PROTOLEARN_LIMITS.maxProbeTimeoutMs)}, or set ${PROTOLEARN_PROBE_TIMEOUT_SETTING}.`,
      },
    );
  const value = Number(configured.trim());
  if (value > PROTOLEARN_LIMITS.maxProbeTimeoutMs)
    throw new ProtolearnProbeConfigurationFailure(
      "invalid_timeout",
      `${PROTOLEARN_PROBE_TIMEOUT_ENV} is above this lane's bound`,
      {
        setting: PROTOLEARN_PROBE_TIMEOUT_ENV,
        configured,
        maximum: PROTOLEARN_LIMITS.maxProbeTimeoutMs,
        remediation: `Set ${PROTOLEARN_PROBE_TIMEOUT_ENV} to at most ${String(PROTOLEARN_LIMITS.maxProbeTimeoutMs)} ms.`,
      },
    );
  return value;
};

/**
 * Resolve the probe lane's interpreter, runner script, operator allowlist, and
 * deadline. Every refusal is fail-closed: an unset allowlist disables probing
 * instead of permitting any endpoint.
 */
export const resolveProtolearnProbeConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
  settingTimeoutMs?: number,
): ProtolearnProbeConfiguration => {
  if (!protolearnSandboxHostSupported())
    throw sandboxUnsupported(process.platform);
  const python = requiredAbsolute(
    environment[PROTOLEARN_PYTHON_ENV],
    "probe_python_not_configured",
    PROTOLEARN_PYTHON_ENV,
    PROTOLEARN_PYTHON_ENV_REMEDIATION,
  );
  const bridgeDirectory = requiredAbsolute(
    environment[PROTOLEARN_BRIDGE_DIR_ENV],
    "bridge_dir_not_configured",
    PROTOLEARN_BRIDGE_DIR_ENV,
    PROTOLEARN_BRIDGE_DIR_REMEDIATION,
  );
  const endpoints = parseProtolearnLabEndpoints(
    environment[PROTOLEARN_LAB_ENDPOINTS_ENV],
  );
  if (!endpoints.ok)
    throw new ProtolearnProbeConfigurationFailure(
      endpoints.error.code === "not_configured"
        ? "lab_endpoints_not_configured"
        : "lab_endpoints_invalid",
      endpoints.error.message,
      {
        setting: PROTOLEARN_LAB_ENDPOINTS_ENV,
        remediation: PROTOLEARN_LAB_ENDPOINTS_REMEDIATION,
      },
      { cause: endpoints.error },
    );
  return {
    python,
    bridgeScript: join(bridgeDirectory, PROTOLEARN_BRIDGE_FILE_NAME),
    endpoints: endpoints.value,
    probeTimeoutMs: probeTimeout(environment, settingTimeoutMs),
  };
};

/**
 * Report the selection without opening a socket or starting the runner.
 *
 * A missing runner script or a non-executable interpreter is reported as
 * unavailable here because both are checked before the first probe.
 */
export const inspectProtolearnProbeConfiguration = async (
  configuration: ProtolearnProbeConfiguration,
): Promise<ProviderAvailability> => {
  try {
    await access(configuration.python, constants.X_OK);
  } catch (cause: unknown) {
    return {
      status: "unavailable",
      code: "executable_missing",
      reason: `${configuration.python} is not an executable interpreter`,
      diagnostics: { cause: cause instanceof Error ? cause.message : null },
    };
  }
  try {
    const script = await stat(configuration.bridgeScript);
    if (!script.isFile())
      return {
        status: "unavailable",
        code: "not_configured",
        reason: `${configuration.bridgeScript} is not a regular file`,
        diagnostics: {},
      };
  } catch (cause: unknown) {
    return {
      status: "unavailable",
      code: "not_configured",
      reason: `${configuration.bridgeScript} is not readable: ${cause instanceof Error ? cause.message : String(cause)}`,
      diagnostics: {},
    };
  }
  return {
    status: "available",
    code: null,
    reason: null,
    diagnostics: {
      interpreter: configuration.python,
      bridge_script: configuration.bridgeScript,
      allowlisted_endpoints: configuration.endpoints.length,
      probe_timeout_ms: configuration.probeTimeoutMs,
      probe: "selection_only",
    },
  };
};

/** Whether the probe lane's selection is complete enough to advertise. */
export const protolearnProbeEnabled = (
  environment: Readonly<Record<string, string | undefined>>,
  injected: boolean,
): boolean => {
  if (injected) return true;
  if (!protolearnSandboxHostSupported()) return false;
  if (!isAbsolute(environment[PROTOLEARN_PYTHON_ENV] ?? "")) return false;
  if (!isAbsolute(environment[PROTOLEARN_BRIDGE_DIR_ENV] ?? "")) return false;
  return parseProtolearnLabEndpoints(environment[PROTOLEARN_LAB_ENDPOINTS_ENV])
    .ok;
};

export const PROTOLEARN_PROBE_REMEDIATION = `${PROTOLEARN_PYTHON_ENV_REMEDIATION} ${PROTOLEARN_BRIDGE_DIR_REMEDIATION} ${PROTOLEARN_LAB_ENDPOINTS_REMEDIATION}`;

export type { ProtolearnConfigurationFailure };
