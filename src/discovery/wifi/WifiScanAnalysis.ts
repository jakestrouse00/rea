import { z } from "zod";

import { err, ok, type Result } from "../../domain/result.js";
import { probeExecutable } from "../DiscoveryConfiguration.js";
import type { ListResult } from "../DiscoveryDeviceOutput.js";
import { DISCOVERY_UNSUPPORTED_HOST_REMEDIATION } from "../DiscoveryRelease.js";

/** Wi-Fi RF lane operation name; the integrator wires this into its switch. */
export const WIFI_SCAN_OPERATION = "scan_wifi_networks" as const;

/** Environment setting carrying the caller-compiled CoreWLAN helper path. */
export const WIFI_SCANNER_SETTING = "REA_WIFI_SCANNER_PATH";

/** Remediation when the RF lane has no caller-built scan helper. */
export const WIFI_SCANNER_REMEDIATION = `${WIFI_SCANNER_SETTING} must name an absolute path to a caller-compiled CoreWLAN scan helper (build with: swiftc -framework CoreWLAN -framework CoreLocation -o ~/.local/share/rea/bin/wifi-scan <rea checkout>/third_party/rea-helpers/wifi-scan.swift; the helper prints one JSON object per observed network and reports macOS location-authorization denial with a {"event":"authorization_required"} stderr row and exit 2). REA never installs or builds the helper; without it the RF lane stays skipped and only the system_profiler fallback is reported.`;

/**
 * Lane input as passed by the provider: already validated against
 * discoveryInputSchemas.scan_wifi_networks, whose defaults fill both fields.
 * Direct callers (tests) may omit them; scan_seconds then falls back to
 * DEFAULT_WIFI_SCAN_SECONDS.
 */
export interface WifiScanInput {
  readonly include_ssid?: boolean;
  readonly scan_seconds?: number;
}

/** One network row as the producer printed it; absent keys are absent facts. */
export const wifiScanRowSchema = z.strictObject({
  ts: z.number().int().nonnegative().nullable(),
  ssid: z.string().min(1).nullable().optional(),
  bssid: z.string().min(1).nullable(),
  rssi: z.number().min(-1000).max(200).nullable(),
  noise: z.number().min(-1000).max(200).nullable(),
  channel: z.number().int().min(1).max(2000).nullable(),
  band: z.enum(["2.4", "5", "6"]).nullable(),
  channel_width_mhz: z.number().int().min(1).max(4000).nullable(),
  phy_mode: z.string().min(1).nullable(),
  security: z.string().min(1).nullable(),
});

export type ParsedWifiNetwork = z.infer<typeof wifiScanRowSchema>;

/** Normalized draft result for scan_wifi_networks (integrator-facing). */
export const wifiScanResultSchema = z.strictObject({
  tools: z.strictObject({
    wifi_scanner: z.string().min(1).nullable(),
    system_profiler: z.string().min(1).nullable(),
  }),
  source: z.enum(["scanner", "system_profiler"]),
  include_ssid: z.boolean(),
  scan_seconds: z.number().int().nonnegative(),
  networks: z.array(wifiScanRowSchema),
  unparsed_lines: z.array(z.string().min(1)),
  coverage: z.enum(["complete", "partial"]),
});

export type WifiScanResult = z.infer<typeof wifiScanResultSchema>;

const EMPTY_LINE = /^\s*$/u;

export interface WifiScanLineOptions {
  readonly includeSsid: boolean;
}

/**
 * Parse one helper run's stdout: one JSON object per line per network, the
 * rows kept verbatim into normalized facts. Non-JSON non-empty lines are
 * preserved in unparsedLines; SSIDs are dropped here, never rewritten, when
 * include_ssid is false.
 */
export const parseWifiScanLines = (
  stdout: string,
  options: WifiScanLineOptions,
): ListResult<ParsedWifiNetwork> => {
  const items: ParsedWifiNetwork[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const row = parseWifiScanRow(line, options);
    if (row === null) {
      unparsedLines.push(line);
      continue;
    }
    items.push(row);
  }
  return { items, unparsedLines };
};

const parseWifiScanRow = (
  line: string,
  options: WifiScanLineOptions,
): ParsedWifiNetwork | null => {
  let candidate: unknown;
  try {
    candidate = JSON.parse(line);
  } catch {
    return null;
  }
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    Array.isArray(candidate)
  )
    return null;
  const record = candidate as Record<string, unknown>;
  if (record["event"] !== undefined) return null;
  const checked = wifiScanRowSchema.safeParse(record);
  if (!checked.success) return null;
  return options.includeSsid ? checked.data : omitSsid(checked.data);
};

const omitSsid = (row: ParsedWifiNetwork): ParsedWifiNetwork => {
  const { ssid: _ssid, ...rest } = row;
  return rest;
};

/**
 * Recognize the helper's structured TCC denial: a stderr JSON row with
 * {"event":"authorization_required"}. Other stderr text is not a denial.
 */
export const isWifiAuthorizationDenial = (stderr: string): boolean =>
  stderr
    .split(/\r?\n/u)
    .some((line) => parseWifiScanEvent(line) === "authorization_required");

/** The helper's stderr event kind for one line; null when it is not one. */
export const parseWifiScanEvent = (line: string): string | null => {
  try {
    const parsed: unknown = JSON.parse(line);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      return null;
    const event = (parsed as Record<string, unknown>)["event"];
    return typeof event === "string" && event.length > 0 ? event : null;
  } catch {
    return null;
  }
};

/**
 * Resolve the optional Wi-Fi RF lane tools: the caller-compiled CoreWLAN
 * helper (probed, absence is not a readiness failure — the lane reports
 * skipped) plus the Apple-shipped system_profiler fallback. A relative
 * REA_WIFI_SCANNER_PATH is refused fail-closed.
 */
export interface WifiScannerResolution {
  readonly scanner: string | null;
  readonly systemProfiler: string | null;
}

export interface WifiScannerReadinessFailure {
  readonly code: "unsupported_host" | "open_options_invalid";
  readonly reason: string;
  readonly setting: string | null;
}

export const resolveWifiScanner = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  {
    platform = process.platform,
    systemProfilerPath,
  }: {
    readonly platform?: NodeJS.Platform;
    readonly systemProfilerPath?: string;
  } = {},
): Promise<Result<WifiScannerResolution, WifiScannerReadinessFailure>> => {
  if (platform !== "darwin")
    return err({
      code: "unsupported_host",
      reason: DISCOVERY_UNSUPPORTED_HOST_REMEDIATION,
      setting: null,
    });
  const raw = environment[WIFI_SCANNER_SETTING];
  if (raw !== undefined && raw.length > 0 && !raw.startsWith("/"))
    return err({
      code: "open_options_invalid",
      reason: `${WIFI_SCANNER_SETTING} must be an absolute path; received ${raw}. ${WIFI_SCANNER_REMEDIATION}`,
      setting: WIFI_SCANNER_SETTING,
    });
  const scanner =
    raw !== undefined && raw.length > 0 && (await probeExecutable(raw))
      ? raw
      : null;
  const profiler = systemProfilerPath ?? "/usr/sbin/system_profiler";
  const systemProfiler = (await probeExecutable(profiler)) ? profiler : null;
  return ok({ scanner, systemProfiler });
};
