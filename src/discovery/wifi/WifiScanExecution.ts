import type { AnalysisExecution } from "../../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../../application/AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisProtocolError } from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  runDiscoveryCommand,
  runDiscoveryObservation,
  type DiscoveryProcessLauncher,
} from "../DiscoveryCommand.js";
import { parseSystemProfilerJson } from "../DiscoveryDeviceOutput.js";
import { DISCOVERY_PROVIDER_ID } from "../DiscoveryRelease.js";
import { DISCOVERY_PROVIDER_IDENTITY } from "../DiscoveryProvider.js";
import {
  isWifiAuthorizationDenial,
  parseWifiScanEvent,
  parseWifiScanLines,
  type ParsedWifiNetwork,
  WIFI_SCAN_OPERATION,
  type WifiScanInput,
} from "./WifiScanAnalysis.js";

/** Fixed grace beyond CoreWLAN's own return; a system scan finishes alone. */
export const WIFI_SCAN_GRACE_MS = 20_000;

/** Default bounded scan window the helper receives as --seconds. */
export const DEFAULT_WIFI_SCAN_SECONDS = 10;

/** One system_profiler airport-table read deadline. */
const SYSTEM_PROFILER_TIMEOUT_MS = 30_000;

export interface WifiScanExecutionOptions {
  readonly scanSeconds?: number;
  /** Full discovery toolset echo for the result's provenance record. */
  readonly toolsEcho?: Record<string, string | null>;
}

/**
 * Run one CoreWLAN helper scan and normalize its JSON rows. Mirrors the
 * blueutil inquiry path: an observation over a bounded deadline, nonzero
 * exits where the helper defined one are observed data (TCC denial, scan
 * error) rather than launcher failures.
 */
export const executeWifiScan = async (
  scannerPath: string,
  input: WifiScanInput,
  signal?: AbortSignal,
  launcher?: DiscoveryProcessLauncher,
  options: WifiScanExecutionOptions = {},
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const scanSeconds =
    options.scanSeconds ?? input.scan_seconds ?? DEFAULT_WIFI_SCAN_SECONDS;
  const ran = await runDiscoveryObservation(
    WIFI_SCAN_OPERATION,
    scannerPath,
    ["--seconds", String(scanSeconds)],
    { timeoutMs: scanSeconds * 1000 + WIFI_SCAN_GRACE_MS },
    signal,
    launcher,
  );
  if (!ran.ok) return ran;
  const { stdout, stderr, exit_code, timed_out } = ran.value;
  if (isWifiAuthorizationDenial(stderr))
    return err(
      new ProviderAdapterError(DISCOVERY_PROVIDER_ID, WIFI_SCAN_OPERATION, {
        userMessage:
          "The Wi-Fi scan helper was refused by macOS Location Services (TCC). Grant location authorization to the process running REA (System Settings, Privacy & Security, Location Services), then run the operation once more; REA does not retry, loop, or work around a denial.",
        remediationAction: "grant_macOS_location_authorization",
      }),
    );
  if (!timed_out && exit_code !== null && exit_code !== 0) {
    const reason = scanFailureReason(stderr);
    return err(
      new ProviderAdapterError(DISCOVERY_PROVIDER_ID, WIFI_SCAN_OPERATION, {
        userMessage: `The Wi-Fi scan helper failed (exit ${String(exit_code)})${
          reason === null ? "" : `: ${reason}`
        }`,
      }),
    );
  }
  const parsed = parseWifiScanLines(stdout, {
    includeSsid: input.include_ssid ?? false,
  });
  const coverage = coverageOf(parsed.unparsedLines, timed_out);
  return ok(
    createAnalysisExecution(
      {
        tools: options.toolsEcho ?? {
          wifi_scanner: scannerPath,
          system_profiler: null,
        },
        source: "scanner",
        include_ssid: input.include_ssid ?? false,
        scan_seconds: scanSeconds,
        networks: parsed.items,
        unparsed_lines: parsed.unparsedLines,
        coverage,
      },
      DISCOVERY_PROVIDER_IDENTITY,
      {
        limitations: scanLimitations(parsed.unparsedLines, timed_out),
      },
    ),
  );
};

/**
 * Fallback RF lane without the CoreWLAN helper: read the host's airport
 * scan cache from system_profiler SPAirPortDataType -json. Neighbor rows
 * under "Other Local Wi-Fi Networks" carry no RF measurements.
 */
export const executeWifiSystemProfiler = async (
  systemProfilerPath: string,
  input: WifiScanInput,
  signal?: AbortSignal,
  launcher?: DiscoveryProcessLauncher,
  options: { readonly toolsEcho?: Record<string, string | null> } = {},
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  const ran = await runDiscoveryCommand(
    WIFI_SCAN_OPERATION,
    systemProfilerPath,
    ["SPAirPortDataType", "-json"],
    { timeoutMs: SYSTEM_PROFILER_TIMEOUT_MS },
    signal,
    launcher,
  );
  if (!ran.ok) return ran;
  const json = parseSystemProfilerJson(ran.value.stdout);
  if (!json.ok)
    return err(
      new AnalysisProtocolError(
        `system_profiler SPAirPortDataType was not recognizable: ${
          json.reason ?? "no JSON"
        }`,
      ),
    );
  const parsed = parseWifiSystemProfilerNetworks(json.data, input);
  const coverage = coverageOf(parsed.unparsedLines, false);
  return ok(
    createAnalysisExecution(
      {
        tools: options.toolsEcho ?? {
          wifi_scanner: null,
          system_profiler: systemProfilerPath,
        },
        source: "system_profiler",
        include_ssid: input.include_ssid ?? false,
        scan_seconds: 0,
        networks: parsed.items,
        unparsed_lines: parsed.unparsedLines,
        coverage,
      },
      DISCOVERY_PROVIDER_IDENTITY,
      {
        limitations: [
          "system_profiler reads this host's airport scan cache; the neighbor list is a stale snapshot, not a live RF scan",
          "The fallback carries no RF measurements: bssid, rssi and noise are null, and neighbor names come verbatim from the producer",
          ...(parsed.unparsedLines.length > 0
            ? [
                "unparsed_lines preserves neighbor records REA did not recognize",
              ]
            : []),
        ],
      },
    ),
  );
};

/** Flatten SPAirPortDataType into neighbor rows plus unparsed records. */
export const parseWifiSystemProfilerNetworks = (
  data: unknown,
  input: WifiScanInput,
): {
  readonly items: ParsedWifiNetwork[];
  readonly unparsedLines: string[];
} => {
  const items: ParsedWifiNetwork[] = [];
  const unparsedLines: string[] = [];
  const payload =
    data !== null &&
    typeof data === "object" &&
    !Array.isArray(data) &&
    Array.isArray((data as Record<string, unknown>)["SPAirPortDataType"])
      ? ((data as Record<string, unknown>)["SPAirPortDataType"] as unknown[])
      : Array.isArray(data)
        ? data
        : [];
  for (const container of payload) {
    for (const neighbors of neighborGroupsOf(container)) {
      for (const neighbor of neighbors) {
        const row = airportNetworkRow(neighbor, input);
        if (row === null) {
          unparsedLines.push(verbatimRecord(neighbor));
          continue;
        }
        items.push(row);
      }
    }
  }
  return { items, unparsedLines };
};

const NEIGHBOR_KEYS = [
  "spairport_airport_other_local_wireless_networks",
  "Other Local Wi-Fi Networks",
] as const;

const neighborGroupsOf = (container: unknown): unknown[][] => {
  if (container === null || typeof container !== "object")
    return Array.isArray(container) ? [container] : [];
  const record = container as Record<string, unknown>;
  const groups = NEIGHBOR_KEYS.map((key) => record[key]);
  const found = groups.find((group) => group !== undefined);
  return Array.isArray(found) ? [found] : [];
};

const airportNetworkRow = (
  neighbor: unknown,
  input: WifiScanInput,
): ParsedWifiNetwork | null => {
  if (
    neighbor === null ||
    typeof neighbor !== "object" ||
    Array.isArray(neighbor)
  )
    return null;
  const record = neighbor as Record<string, unknown>;
  const channel = parseSpairportChannel(record["spairport_network_channel"]);
  if (channel === null && record["spairport_network_channel"] === undefined)
    return null;
  return {
    ts: null,
    ...(input.include_ssid ? { ssid: airportString(record["_name"]) } : {}),
    bssid: null,
    rssi: null,
    noise: null,
    channel: channel?.channel ?? null,
    band: channel?.band ?? null,
    channel_width_mhz: channel?.width ?? null,
    phy_mode: airportString(record["spairport_network_phymode"]),
    security: airportString(record["spairport_security_mode"]),
  };
};

const airportString = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

/** `52 (5GHz, 80MHz)` -> {channel: 52, band: "5", width: 80}; null otherwise. */
export const parseSpairportChannel = (
  value: unknown,
): {
  readonly channel: number;
  readonly band: "2.4" | "5" | "6" | null;
  readonly width: number | null;
} | null => {
  if (typeof value !== "string") return null;
  const match =
    /^(\d+)\s*\(\s*([^,)]*?)(?:\s*,\s*([0-9.]+)\s*MHz)?\s*\)$/u.exec(
      value.trim(),
    );
  if (match === null) return null;
  const channel = Number.parseInt(match[1] ?? "", 10);
  if (!Number.isInteger(channel)) return null;
  return {
    channel,
    band: bandOfToken(match[2] ?? ""),
    width: match[3] === undefined ? null : Number.parseFloat(match[3]) || null,
  };
};

const bandOfToken = (token: string): "2.4" | "5" | "6" | null => {
  const normalized = token.trim().toLowerCase();
  if (normalized === "2ghz" || normalized === "2.4ghz") return "2.4";
  if (normalized === "5ghz") return "5";
  if (normalized === "6ghz") return "6";
  return null;
};

const verbatimRecord = (value: unknown): string => {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
};

const scanFailureReason = (stderr: string): string | null => {
  for (const line of stderr.split(/\r?\n/u).reverse()) {
    const event = parseWifiScanEvent(line);
    if (event === null) continue;
    try {
      const parsed = JSON.parse(line) as { reason?: unknown };
      const reason =
        typeof parsed["reason"] === "string" ? parsed["reason"] : null;
      if (reason === null) return line;
      return `${event}: ${reason}`;
    } catch {
      return line;
    }
  }
  return stderr.trim().length > 0 ? stderr.trim() : null;
};

const coverageOf = (unparsedLines: string[], timedOut: boolean) =>
  unparsedLines.length > 0 || timedOut
    ? ("partial" as const)
    : ("complete" as const);

const scanLimitations = (unparsedLines: string[], timedOut: boolean) => [
  "The CoreWLAN helper is caller-built and runs unprivileged, but macOS gates neighbor scans behind Location Services authorization; a TCC denial is reported as a structured failure, never retried or worked around",
  "On this macOS 27 host the verification scan returned rows whose bssid and ssid were both withheld (null) because the process lacked Location authorization; withheld identifying fields are preserved verbatim as nulls",
  "CoreWLAN scan results expose no per-network PHY mode or security property in the public SDK, so phy_mode and security stay null in the scanner lane and are supplied as verbatim strings only by the system_profiler fallback",
  "Scan-result noiseMeasurement is typically 0 for networks other than this host's association; rows carry the producer's value verbatim",
  ...(timedOut
    ? [
        "The scan exceeded its bounded observation deadline; rows captured before the deadline were kept and coverage is partial",
      ]
    : []),
  ...(unparsedLines.length > 0
    ? [
        "unparsed_lines preserves helper output REA did not recognize as a network row",
      ]
    : []),
];
