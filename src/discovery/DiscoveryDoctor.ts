import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import {
  inspectDiscoveryInstallation,
  type DiscoveryReadinessFailure,
} from "./DiscoveryInstallation.js";
import {
  DISCOVERY_LANE_NOTE,
  DISCOVERY_PROVIDER_ID,
  DISCOVERY_TOOL_REMEDIATION,
  DISCOVERY_UNSUPPORTED_HOST_REMEDIATION,
} from "./DiscoveryRelease.js";

/** Settings a registration may carry; only those the caller set explicitly. */
const REGISTRATION_SETTINGS = [
  "REA_ARP_PATH",
  "REA_NDP_PATH",
  "REA_DNS_SD_PATH",
  "REA_SYSTEM_PROFILER_PATH",
  "REA_PING_PATH",
  "REA_IFCONFIG_PATH",
  "REA_BLUEUTIL_PATH",
  "REA_BLE_SCANNER_PATH",
  "REA_BLE_GATT_PATH",
  "REA_WIFI_SCANNER_PATH",
  "REA_STTY_PATH",
  "REA_PACKET_CAPTURE_COMMAND",
] as const;

/**
 * Project discovery-lane readiness into the doctor contract without
 * reading host tables or contacting devices. blueutil absence is not a
 * failure: the inquiry source stays skipped instead.
 */
export const inspectDiscoveryProvider = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
  _options: {
    readonly resourceScope: RetainedResourceScope;
    readonly signal?: AbortSignal;
  },
): Promise<DoctorProviderInspection> => {
  const configured = REGISTRATION_SETTINGS.some(
    (name) => environment[name] !== undefined && environment[name]!.length > 0,
  );
  const registrationEnvironment = Object.fromEntries(
    REGISTRATION_SETTINGS.flatMap((name) => {
      const setting = environment[name];
      return setting === undefined ? [] : [[name, setting]];
    }),
  );
  let installation: Awaited<ReturnType<typeof inspectDiscoveryInstallation>>;
  try {
    installation = await inspectDiscoveryInstallation(environment, {
      platform,
    });
  } catch (cause: unknown) {
    return {
      id: DISCOVERY_PROVIDER_ID,
      configured,
      available: false,
      providerVersion: null,
      registrationEnvironment,
      checks: [
        {
          name: "installation",
          ok: false,
          code: "executable_missing",
          detail: `The discovery toolset verification failed: ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
          remediation: DISCOVERY_TOOL_REMEDIATION,
          classification: configured
            ? ("config_drift" as const)
            : ("missing_analysis_engine" as const),
        },
      ],
    };
  }
  if (!installation.ok)
    return {
      id: DISCOVERY_PROVIDER_ID,
      configured,
      available: false,
      providerVersion: null,
      registrationEnvironment,
      checks: [installationFailureCheck(installation.error, configured)],
    };
  const { tools } = installation.value;
  return {
    id: DISCOVERY_PROVIDER_ID,
    configured,
    available: true,
    providerVersion: null,
    registrationEnvironment,
    checks: [
      {
        name: "installation",
        ok: true,
        code: null,
        detail: `Host tools resolved: arp, ndp, dns-sd, system_profiler, ping, ifconfig${
          tools.blueutil === null
            ? "; blueutil not configured, so the Bluetooth inquiry source stays skipped"
            : `; blueutil at ${tools.blueutil}`
        }${
          tools.bleScanner === null
            ? "; BLE scanner not configured, so the BLE advertisement scan source stays skipped"
            : `; BLE scanner at ${tools.bleScanner}`
        }${
          tools.bleGatt === null
            ? "; GATT helper not configured, so the BLE GATT session tools stay skipped"
            : `; GATT helper at ${tools.bleGatt}`
        }${
          tools.packetCapture === null
            ? "; capture program not configured, so packet capture stays unavailable"
            : `; capture program at ${tools.packetCapture}`
        }${
          tools.stty === null
            ? "; stty not found, so the serial observe source is refused on use"
            : `; stty at ${tools.stty}`
        }. ${DISCOVERY_LANE_NOTE}`,
        remediation: null,
        classification: "config_drift" as const,
        details: {
          arp: tools.arp,
          ndp: tools.ndp,
          dns_sd: tools.dnsSd,
          system_profiler: tools.systemProfiler,
          ping: tools.ping,
          ifconfig: tools.ifconfig,
          ...(tools.stty === null ? {} : { stty: tools.stty }),
          ...(tools.blueutil === null ? {} : { blueutil: tools.blueutil }),
          ...(tools.bleScanner === null
            ? {}
            : { ble_scanner: tools.bleScanner }),
          ...(tools.bleGatt === null ? {} : { ble_gatt: tools.bleGatt }),
          ...(tools.packetCapture === null
            ? {}
            : { packet_capture: tools.packetCapture }),
        },
      },
    ],
  };
};

const installationFailureCheck = (
  failure: DiscoveryReadinessFailure,
  configured: boolean,
): DoctorProviderCheck => ({
  name: "installation",
  ok: false,
  code: failure.code,
  detail: failure.reason,
  remediation:
    failure.code === "unsupported_host"
      ? DISCOVERY_UNSUPPORTED_HOST_REMEDIATION
      : DISCOVERY_TOOL_REMEDIATION,
  classification:
    failure.code === "unsupported_host"
      ? "unsupported_host"
      : configured
        ? "config_drift"
        : "missing_analysis_engine",
  details: { ...failure.diagnostics },
});
