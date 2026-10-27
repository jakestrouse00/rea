import { constants } from "node:fs";
import { access, realpath } from "node:fs/promises";

import { err, ok, type Result } from "../domain/result.js";
import {
  DISCOVERY_BLUEUTIL_REMEDIATION,
  DISCOVERY_TOOL_REMEDIATION,
  DISCOVERY_UNSUPPORTED_HOST_REMEDIATION,
} from "./DiscoveryRelease.js";

/** One-shot probe or table read deadline. */
const DEFAULT_OPERATION_TIMEOUT_MS = 30_000;

/** One bounded mDNS browse window for one dns-sd process. */
const DEFAULT_DNS_SD_TIMEOUT_MS = 40_000;

/** Caller-overridable absolute path resolution record per tool. */
export interface DiscoveryConfiguration {
  readonly arp: string;
  readonly ndp: string;
  readonly dnsSd: string;
  readonly systemProfiler: string;
  readonly ping: string;
  /** Caller-supplied blueutil; absent means the inquiry source stays skipped. */
  readonly blueutil: string | null;
  readonly operationTimeoutMs: number;
  readonly browseProcessTimeoutMs: number;
}

/** Why the configured environment cannot select the host tools. */
export interface DiscoveryConfigurationFailure {
  readonly code:
    | "unsupported_host"
    | "open_options_invalid"
    | "executable_missing";
  readonly reason: string;
  readonly setting: string | null;
}

const failure = (
  code: DiscoveryConfigurationFailure["code"],
  reason: string,
  setting: string | null = null,
): Result<never, DiscoveryConfigurationFailure> =>
  err({ code, reason, setting });

/** Candidate absolute paths per host tool, in preference order. */
const TOOL_CANDIDATES: Readonly<
  Record<"arp" | "ndp" | "dnsSd" | "systemProfiler" | "ping", readonly string[]>
> = {
  arp: ["/usr/sbin/arp", "/sbin/arp"],
  ndp: ["/usr/sbin/ndp", "/sbin/ndp"],
  dnsSd: ["/usr/bin/dns-sd"],
  systemProfiler: ["/usr/sbin/system_profiler"],
  ping: ["/sbin/ping", "/usr/sbin/ping"],
};

const ENV_OVERRIDE: Readonly<Record<keyof typeof TOOL_CANDIDATES, string>> = {
  arp: "REA_ARP_PATH",
  ndp: "REA_NDP_PATH",
  dnsSd: "REA_DNS_SD_PATH",
  systemProfiler: "REA_SYSTEM_PROFILER_PATH",
  ping: "REA_PING_PATH",
};

const isAbsolute = (p: string): boolean => p.startsWith("/");

const resolveOne = (
  setting: string,
  candidates: readonly string[],
): { path: string } | { error: string } => {
  for (const candidate of candidates) {
    if (isAbsolute(candidate)) return { path: candidate };
  }
  return {
    error: `No standard absolute path exists for ${setting}; set an override. ${DISCOVERY_TOOL_REMEDIATION}`,
  };
};

/**
 * Parse the discovery settings without touching the filesystem. Paths are
 * resolved from explicit environment overrides or Apple's standard absolute
 * locations; relative values are refused fail-closed.
 */
export const readDiscoveryConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): Result<DiscoveryConfiguration, DiscoveryConfigurationFailure> => {
  if (platform !== "darwin")
    return failure("unsupported_host", DISCOVERY_UNSUPPORTED_HOST_REMEDIATION);

  const resolved = {} as Record<keyof typeof TOOL_CANDIDATES, string>;
  for (const key of Object.keys(
    TOOL_CANDIDATES,
  ) as (keyof typeof TOOL_CANDIDATES)[]) {
    const override = environment[ENV_OVERRIDE[key]];
    const setting = ENV_OVERRIDE[key];
    if (override !== undefined && override.length > 0) {
      if (!isAbsolute(override))
        return failure(
          "open_options_invalid",
          `${setting} must be an absolute path; received ${override}. ${DISCOVERY_TOOL_REMEDIATION}`,
          setting,
        );
      resolved[key] = override;
      continue;
    }
    const found = resolveOne(setting, TOOL_CANDIDATES[key]);
    if ("error" in found)
      return failure("executable_missing", found.error, setting);
    resolved[key] = found.path;
  }

  const blueutilRaw = environment.REA_BLUEUTIL_PATH;
  if (
    blueutilRaw !== undefined &&
    blueutilRaw.length > 0 &&
    !isAbsolute(blueutilRaw)
  )
    return failure(
      "open_options_invalid",
      `REA_BLUEUTIL_PATH must be an absolute path; received ${blueutilRaw}. ${DISCOVERY_BLUEUTIL_REMEDIATION}`,
      "REA_BLUEUTIL_PATH",
    );

  return ok({
    arp: resolved.arp!,
    ndp: resolved.ndp!,
    dnsSd: resolved.dnsSd!,
    systemProfiler: resolved.systemProfiler!,
    ping: resolved.ping!,
    blueutil:
      blueutilRaw === undefined || blueutilRaw.length === 0
        ? null
        : blueutilRaw,
    operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS,
    browseProcessTimeoutMs: DEFAULT_DNS_SD_TIMEOUT_MS,
  });
};

/** Existence/executability check shared by readiness and doctor. */
export const probeExecutable = async (path: string): Promise<boolean> => {
  try {
    const canonical = await realpath(path);
    await access(canonical, constants.X_OK);
    return true;
  } catch {
    return false;
  }
};
