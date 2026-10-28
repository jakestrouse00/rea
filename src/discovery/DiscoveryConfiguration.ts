import { constants } from "node:fs";
import { access, realpath } from "node:fs/promises";

import { err, ok, type Result } from "../domain/result.js";
import {
  DISCOVERY_BLEAK_REMEDIATION,
  DISCOVERY_BLE_GATT_REMEDIATION,
  DISCOVERY_BLE_REMEDIATION,
  DISCOVERY_BLUEUTIL_REMEDIATION,
  DISCOVERY_CAPTURE_REMEDIATION,
  DISCOVERY_TOOL_REMEDIATION,
  DISCOVERY_UNSUPPORTED_HOST_REMEDIATION,
  DISCOVERY_WIFI_REMEDIATION,
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
  readonly ifconfig: string;
  /** Caller-supplied blueutil; absent means the inquiry source stays skipped. */
  readonly blueutil: string | null;
  /** Caller-supplied BLE scanner; absent means the BLE scan source stays skipped. */
  readonly bleScanner: string | null;
  /** Caller-supplied CoreWLAN helper; absent means the RF lane uses the fallback. */
  readonly wifiScanner: string | null;
  /**
   * Caller-supplied CoreBluetooth GATT helper; absent means the GATT session
   * tools stay skipped unless the bundled bleak bridge is selected.
   */
  readonly bleGatt: string | null;
  /**
   * Caller-supplied Python 3 with bleak installed, which runs the bundled
   * bridge at bridge/ble/bleak_bridge.py; absent means the bundled bridge is
   * not selected.
   */
  readonly bleakPython: string | null;
  /** stty, needed only by the serial observe window; absent means it is refused. */
  readonly stty: string | null;
  /** Caller-supplied capture program; absent means capture stays unavailable. */
  readonly packetCapture: string | null;
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
  Record<
    "arp" | "ndp" | "dnsSd" | "systemProfiler" | "ping" | "ifconfig",
    readonly string[]
  >
> = {
  arp: ["/usr/sbin/arp", "/sbin/arp"],
  ndp: ["/usr/sbin/ndp", "/sbin/ndp"],
  dnsSd: ["/usr/bin/dns-sd"],
  systemProfiler: ["/usr/sbin/system_profiler"],
  ping: ["/sbin/ping", "/usr/sbin/ping"],
  ifconfig: ["/sbin/ifconfig"],
};

const ENV_OVERRIDE: Readonly<Record<keyof typeof TOOL_CANDIDATES, string>> = {
  arp: "REA_ARP_PATH",
  ndp: "REA_NDP_PATH",
  dnsSd: "REA_DNS_SD_PATH",
  systemProfiler: "REA_SYSTEM_PROFILER_PATH",
  ping: "REA_PING_PATH",
  ifconfig: "REA_IFCONFIG_PATH",
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

  const bleScannerRaw = environment.REA_BLE_SCANNER_PATH;
  if (
    bleScannerRaw !== undefined &&
    bleScannerRaw.length > 0 &&
    !isAbsolute(bleScannerRaw)
  )
    return failure(
      "open_options_invalid",
      `REA_BLE_SCANNER_PATH must be an absolute path; received ${bleScannerRaw}. ${DISCOVERY_BLE_REMEDIATION}`,
      "REA_BLE_SCANNER_PATH",
    );

  const packetCaptureRaw = environment.REA_PACKET_CAPTURE_COMMAND;
  if (
    packetCaptureRaw !== undefined &&
    packetCaptureRaw.length > 0 &&
    !isAbsolute(packetCaptureRaw)
  )
    return failure(
      "open_options_invalid",
      `REA_PACKET_CAPTURE_COMMAND must be an absolute path; received ${packetCaptureRaw}. ${DISCOVERY_CAPTURE_REMEDIATION}`,
      "REA_PACKET_CAPTURE_COMMAND",
    );

  const wifiScannerRaw = environment.REA_WIFI_SCANNER_PATH;
  if (
    wifiScannerRaw !== undefined &&
    wifiScannerRaw.length > 0 &&
    !isAbsolute(wifiScannerRaw)
  )
    return failure(
      "open_options_invalid",
      `REA_WIFI_SCANNER_PATH must be an absolute path; received ${wifiScannerRaw}. ${DISCOVERY_WIFI_REMEDIATION}`,
      "REA_WIFI_SCANNER_PATH",
    );

  const bleGattRaw = environment.REA_BLE_GATT_PATH;
  if (
    bleGattRaw !== undefined &&
    bleGattRaw.length > 0 &&
    !isAbsolute(bleGattRaw)
  )
    return failure(
      "open_options_invalid",
      `REA_BLE_GATT_PATH must be an absolute path; received ${bleGattRaw}. ${DISCOVERY_BLE_GATT_REMEDIATION}`,
      "REA_BLE_GATT_PATH",
    );

  const bleakPythonRaw = environment.REA_BLEAK_PYTHON;
  if (
    bleakPythonRaw !== undefined &&
    bleakPythonRaw.length > 0 &&
    !isAbsolute(bleakPythonRaw)
  )
    return failure(
      "open_options_invalid",
      `REA_BLEAK_PYTHON must be an absolute path; received ${bleakPythonRaw}. ${DISCOVERY_BLEAK_REMEDIATION}`,
      "REA_BLEAK_PYTHON",
    );

  const sttyRaw = environment.REA_STTY_PATH;
  if (sttyRaw !== undefined && sttyRaw.length > 0 && !isAbsolute(sttyRaw))
    return failure(
      "open_options_invalid",
      `REA_STTY_PATH must be an absolute path; received ${sttyRaw}. The serial lane resolves stty at its standard macOS locations otherwise.`,
      "REA_STTY_PATH",
    );

  return ok({
    arp: resolved.arp!,
    ndp: resolved.ndp!,
    dnsSd: resolved.dnsSd!,
    systemProfiler: resolved.systemProfiler!,
    ping: resolved.ping!,
    ifconfig: resolved.ifconfig!,
    blueutil:
      blueutilRaw === undefined || blueutilRaw.length === 0
        ? null
        : blueutilRaw,
    bleScanner:
      bleScannerRaw === undefined || bleScannerRaw.length === 0
        ? null
        : bleScannerRaw,
    packetCapture:
      packetCaptureRaw === undefined || packetCaptureRaw.length === 0
        ? null
        : packetCaptureRaw,
    wifiScanner:
      wifiScannerRaw === undefined || wifiScannerRaw.length === 0
        ? null
        : wifiScannerRaw,
    bleGatt:
      bleGattRaw === undefined || bleGattRaw.length === 0 ? null : bleGattRaw,
    bleakPython:
      bleakPythonRaw === undefined || bleakPythonRaw.length === 0
        ? null
        : bleakPythonRaw,
    stty: sttyRaw === undefined || sttyRaw.length === 0 ? "/bin/stty" : sttyRaw,
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
