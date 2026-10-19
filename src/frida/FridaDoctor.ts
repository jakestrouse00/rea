import type { JsonValue } from "../domain/jsonValue.js";
import {
  probeFridaRuntimeVersion,
  FRIDA_PROVIDER_ID,
  FRIDA_RUNTIME_PROBE_REMEDIATION,
  FRIDA_VERIFIED_VERSION,
} from "./FridaRelease.js";

/**
 * Project the local frida Node binding's readiness into the doctor contract
 * without writing anything. The binding ships with REA's own dependencies, so
 * the probe never installs or upgrades it.
 */
export const inspectFridaRuntimeProvider = async (): Promise<{
  readonly id: typeof FRIDA_PROVIDER_ID;
  readonly configured: boolean;
  readonly available: boolean;
  readonly providerVersion: string | null;
  readonly registrationEnvironment: Record<string, string>;
  readonly checks: readonly {
    readonly name: string;
    readonly ok: boolean;
    readonly code: string | null;
    readonly detail: string;
    readonly remediation: string | null;
    readonly classification: "config_drift" | "missing_analysis_engine";
    readonly details?: Readonly<Record<string, JsonValue>>;
  }[];
}> => {
  const version = await probeFridaRuntimeVersion();
  if (version === null)
    return {
      id: FRIDA_PROVIDER_ID,
      configured: true,
      available: false,
      providerVersion: null,
      registrationEnvironment: {},
      checks: [
        {
          name: "runtime",
          ok: false,
          code: "runtime_unavailable",
          detail: `The frida Node binding could not be loaded or did not report a version; the observed release is unknown.`,
          remediation: FRIDA_RUNTIME_PROBE_REMEDIATION,
          classification: "missing_analysis_engine",
        },
      ],
    };
  return {
    id: FRIDA_PROVIDER_ID,
    configured: true,
    available: true,
    providerVersion: version,
    registrationEnvironment: {},
    checks: [
      {
        name: "runtime",
        ok: true,
        code: null,
        detail: `frida Node binding reports ${version}${
          version === FRIDA_VERIFIED_VERSION
            ? " (this is the release REA verified)."
            : `; REA verified ${FRIDA_VERIFIED_VERSION}, so this release's behavior is unverified.`
        }`,
        remediation: null,
        classification: "config_drift",
        details: {
          version,
          verified_version: FRIDA_VERIFIED_VERSION,
        },
      },
    ],
  };
};
