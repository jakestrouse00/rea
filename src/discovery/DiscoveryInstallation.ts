import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  readDiscoveryConfiguration,
  probeExecutable,
  type DiscoveryConfiguration,
  type DiscoveryConfigurationFailure,
} from "./DiscoveryConfiguration.js";
import { DISCOVERY_TOOL_REMEDIATION } from "./DiscoveryRelease.js";

/**
 * One resolved discovery toolset: Apple-shipped host tools selected at
 * absolute paths (optionally overridden) that all exist and are
 * executable, plus the optional caller-supplied blueutil.
 */
export interface DiscoveryInstallation {
  readonly configuration: DiscoveryConfiguration;
  readonly tools: {
    readonly arp: string;
    readonly ndp: string;
    readonly dnsSd: string;
    readonly systemProfiler: string;
    readonly ping: string;
    readonly blueutil: string | null;
  };
}

/** Why the toolset cannot be used. */
export interface DiscoveryReadinessFailure {
  readonly code: DiscoveryConfigurationFailure["code"] | "executable_missing";
  readonly reason: string;
  readonly diagnostics: Readonly<Record<string, JsonValue>>;
}

export interface DiscoveryInstallationOptions {
  readonly platform?: NodeJS.Platform;
}

const failure = (
  code: DiscoveryReadinessFailure["code"],
  reason: string,
  diagnostics: Readonly<Record<string, JsonValue>>,
): Result<never, DiscoveryReadinessFailure> =>
  err({ code, reason, diagnostics });

const REQUIRED = [
  ["arp", "REA_ARP_PATH"],
  ["ndp", "REA_NDP_PATH"],
  ["dnsSd", "REA_DNS_SD_PATH"],
  ["systemProfiler", "REA_SYSTEM_PROFILER_PATH"],
  ["ping", "REA_PING_PATH"],
] as const;

/**
 * Resolve and verify the discovery toolset without reading host tables or
 * contacting devices. blueutil presence is probed, but its absence is not
 * a readiness failure: the paired Bluetooth source works without it.
 */
export const inspectDiscoveryInstallation = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: DiscoveryInstallationOptions = {},
): Promise<Result<DiscoveryInstallation, DiscoveryReadinessFailure>> => {
  const configuration = readDiscoveryConfiguration(
    environment,
    options.platform,
  );
  if (!configuration.ok)
    return failure(configuration.error.code, configuration.error.reason, {
      configured: configuration.error.code !== "executable_missing",
      ...(configuration.error.setting === null
        ? {}
        : { setting: configuration.error.setting }),
    });
  const { value } = configuration;

  for (const [key, setting] of REQUIRED) {
    const path = value[key];
    if (await probeExecutable(path)) continue;
    return failure(
      "executable_missing",
      `${setting} resolves to ${path}, which is missing or not executable. ${DISCOVERY_TOOL_REMEDIATION}`,
      { setting, path },
    );
  }

  let blueutil: string | null = null;
  if (value.blueutil !== null) {
    if (await probeExecutable(value.blueutil)) blueutil = value.blueutil;
  }

  return ok({
    configuration: value,
    tools: {
      arp: value.arp,
      ndp: value.ndp,
      dnsSd: value.dnsSd,
      systemProfiler: value.systemProfiler,
      ping: value.ping,
      blueutil,
    },
  });
};
