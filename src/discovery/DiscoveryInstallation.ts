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
 * executable, plus the optional caller-supplied blueutil and BLE scanner.
 */
export interface DiscoveryInstallation {
  readonly configuration: DiscoveryConfiguration;
  readonly tools: {
    readonly arp: string;
    readonly ndp: string;
    readonly dnsSd: string;
    readonly systemProfiler: string;
    readonly ping: string;
    readonly ifconfig: string;
    readonly blueutil: string | null;
    readonly bleScanner: string | null;
    readonly wifiScanner: string | null;
    readonly bleGatt: string | null;
    readonly bleakPython: string | null;
    readonly stty: string | null;
    readonly packetCapture: string | null;
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
  ["ifconfig", "REA_IFCONFIG_PATH"],
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

  let bleScanner: string | null = null;
  if (value.bleScanner !== null) {
    if (await probeExecutable(value.bleScanner)) bleScanner = value.bleScanner;
  }

  let wifiScanner: string | null = null;
  if (value.wifiScanner !== null) {
    if (await probeExecutable(value.wifiScanner))
      wifiScanner = value.wifiScanner;
  }

  let bleGatt: string | null = null;
  if (value.bleGatt !== null) {
    if (await probeExecutable(value.bleGatt)) bleGatt = value.bleGatt;
  }

  let bleakPython: string | null = null;
  if (value.bleakPython !== null) {
    if (await probeExecutable(value.bleakPython)) bleakPython = value.bleakPython;
  }

  let stty: string | null = null;
  if (value.stty !== null) {
    if (await probeExecutable(value.stty)) stty = value.stty;
  }

  let packetCapture: string | null = null;
  if (value.packetCapture !== null) {
    if (await probeExecutable(value.packetCapture))
      packetCapture = value.packetCapture;
  }

  return ok({
    configuration: value,
    tools: {
      arp: value.arp,
      ndp: value.ndp,
      dnsSd: value.dnsSd,
      systemProfiler: value.systemProfiler,
      ping: value.ping,
      ifconfig: value.ifconfig,
      blueutil,
      bleScanner,
      wifiScanner,
      bleGatt,
      bleakPython,
      stty,
      packetCapture,
    },
  });
};
