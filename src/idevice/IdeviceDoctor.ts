import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import {
  inspectIdeviceInstallation,
  type IdeviceReadinessFailure,
} from "./IdeviceInstallation.js";
import {
  IDEVICE_COMMAND_REMEDIATION,
  IDEVICE_LANE_UNVERIFIED_NOTE,
  IDEVICE_PROVIDER_ID,
  IDEVICE_UNSUPPORTED_HOST_REMEDIATION,
  IDEVICE_VERSION_PROBE_REMEDIATION,
  IDEVICE_VERIFIED_VERSION,
} from "./IdeviceRelease.js";

/** Settings a registration may carry; only those the caller set explicitly. */
const REGISTRATION_SETTINGS = [
  "REA_IPHONE_PMD3_COMMAND",
  "REA_IDEVICE_TIMEOUT_MS",
] as const;

/**
 * Project iOS device plane readiness into the doctor contract without writing
 * anything. The probe verifies the command's presence and version only; the
 * device inventory is not contacted (an unpaired host stays healthy).
 */
export const inspectIdeviceProvider = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
  _options: {
    readonly resourceScope: RetainedResourceScope;
    readonly signal?: AbortSignal;
  },
): Promise<DoctorProviderInspection> => {
  const configured =
    environment.REA_IPHONE_PMD3_COMMAND !== undefined &&
    environment.REA_IPHONE_PMD3_COMMAND.length > 0;
  const registrationEnvironment = Object.fromEntries(
    REGISTRATION_SETTINGS.flatMap((name) => {
      const setting = environment[name];
      return setting === undefined ? [] : [[name, setting]];
    }),
  );
  let installation: Awaited<ReturnType<typeof inspectIdeviceInstallation>>;
  try {
    installation = await inspectIdeviceInstallation(environment, { platform });
  } catch (cause: unknown) {
    return {
      id: IDEVICE_PROVIDER_ID,
      configured,
      available: false,
      providerVersion: null,
      registrationEnvironment,
      checks: [
        {
          name: "installation",
          ok: false,
          code: "version_unresolved",
          detail: `The pymobiledevice3 readiness probe failed: ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
          remediation: IDEVICE_VERSION_PROBE_REMEDIATION,
          classification: configured
            ? ("config_drift" as const)
            : ("missing_analysis_engine" as const),
        },
      ],
    };
  }
  if (!installation.ok)
    return {
      id: IDEVICE_PROVIDER_ID,
      configured,
      available: false,
      providerVersion: null,
      registrationEnvironment,
      checks: [installationFailureCheck(installation.error, configured)],
    };
  const { value } = installation;
  return {
    id: IDEVICE_PROVIDER_ID,
    configured,
    available: true,
    providerVersion: value.version,
    registrationEnvironment,
    checks: [
      {
        name: "installation",
        ok: true,
        code: null,
        detail: `${value.executable} reports pymobiledevice3 ${value.version}${
          IDEVICE_VERIFIED_VERSION === null
            ? "; no REA-verified iOS device plane release exists yet, so this release is unverified."
            : value.verified
              ? " (this is the release REA verified)."
              : `; REA verified ${IDEVICE_VERIFIED_VERSION}, so this release's device behavior is unverified.`
        } ${IDEVICE_LANE_UNVERIFIED_NOTE}`,
        remediation: null,
        classification: "config_drift" as const,
        details: {
          executable: value.executable,
          version: value.version,
          verified_version: IDEVICE_VERIFIED_VERSION,
        },
      },
    ],
  };
};

const installationFailureCheck = (
  failure: IdeviceReadinessFailure,
  configured: boolean,
): DoctorProviderCheck => ({
  name: "installation",
  ok: false,
  code: failure.code,
  detail: failure.reason,
  remediation:
    failure.code === "unsupported_host"
      ? IDEVICE_UNSUPPORTED_HOST_REMEDIATION
      : failure.code === "version_unresolved"
        ? IDEVICE_VERSION_PROBE_REMEDIATION
        : IDEVICE_COMMAND_REMEDIATION,
  classification:
    failure.code === "unsupported_host"
      ? "unsupported_host"
      : configured
        ? "config_drift"
        : "missing_analysis_engine",
  details: { ...failure.diagnostics },
});
