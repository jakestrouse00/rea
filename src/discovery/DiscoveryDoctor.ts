import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import type { FileCloseResourceOwner } from "../application/AnalysisProvider.js";
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
  "REA_BLUEUTIL_PATH",
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
    readonly fileCloseResources: FileCloseResourceOwner;
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
        detail: `Host tools resolved: arp, ndp, dns-sd, system_profiler, ping${
          tools.blueutil === null
            ? "; blueutil not configured, so the Bluetooth inquiry source stays skipped"
            : `; blueutil at ${tools.blueutil}`
        }. ${DISCOVERY_LANE_NOTE}`,
        remediation: null,
        classification: "config_drift" as const,
        details: {
          arp: tools.arp,
          ndp: tools.ndp,
          dns_sd: tools.dnsSd,
          system_profiler: tools.systemProfiler,
          ping: tools.ping,
          ...(tools.blueutil === null ? {} : { blueutil: tools.blueutil }),
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
