import { stat } from "node:fs/promises";

import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import { execFileOutput } from "../process/ExecFileOutput.js";
import {
  LIEF_BRIDGE_DIR_ENV,
  LIEF_BRIDGE_FILE_NAME,
  LIEF_COMMAND_ENV,
  LIEF_COMMAND_REMEDIATION,
  LIEF_IMPORT_REMEDIATION,
  LIEF_LIMITS,
  LIEF_PROVIDER_ID,
} from "../domain/lief/liefLimits.js";
import {
  LIEF_SUPPORTED_RANGE,
  liefVersionSupported,
  parseLiefVersion,
} from "../domain/lief/liefVersion.js";
import { resolveLiefConfiguration } from "./LiefConfiguration.js";

/** Settings a registration may carry; only those the caller set explicitly. */
const REGISTRATION_SETTINGS = [LIEF_COMMAND_ENV, LIEF_BRIDGE_DIR_ENV] as const;

/** One-line probe: the interpreter must import LIEF and print its version. */
const PROBE_SOURCE =
  "import json, lief; print(json.dumps({'version': lief.__version__}))";

const failureCheck = (
  code: string,
  detail: string,
  remediation: string,
  classification: "missing_analysis_engine" | "config_drift",
): DoctorProviderCheck => ({
  name: "installation",
  ok: false,
  code,
  detail,
  remediation,
  classification,
});

const unavailable = (
  configured: boolean,
  checks: readonly DoctorProviderCheck[],
): DoctorProviderInspection => ({
  id: LIEF_PROVIDER_ID,
  configured,
  available: false,
  providerVersion: null,
  registrationEnvironment: {},
  checks,
});

/** Why the selected interpreter and bridge cannot serve a request. */
type LiefReadiness =
  | { readonly ok: true; readonly version: string; readonly command: string }
  | { readonly ok: false; readonly check: DoctorProviderCheck };

const probeInterpreter = async (command: string): Promise<LiefReadiness> => {
  try {
    const stats = await stat(command);
    if (!stats.isFile())
      return {
        ok: false,
        check: failureCheck(
          "invalid_path",
          `${LIEF_COMMAND_ENV} is not a regular file: ${command}.`,
          LIEF_COMMAND_REMEDIATION,
          "config_drift",
        ),
      };
  } catch {
    return {
      ok: false,
      check: failureCheck(
        "executable_missing",
        `${LIEF_COMMAND_ENV} does not exist: ${command}.`,
        LIEF_COMMAND_REMEDIATION,
        "config_drift",
      ),
    };
  }
  try {
    const output = await execFileOutput(command, ["-B", "-c", PROBE_SOURCE], {
      timeout: LIEF_LIMITS.doctorProbeTimeoutMs,
      maxBuffer: LIEF_LIMITS.doctorProbeMaxBytes,
    });
    const decoded: unknown = JSON.parse(
      output.stdout.split(/\r?\n/u, 1)[0] ?? "",
    );
    const version =
      typeof decoded === "object" &&
      decoded !== null &&
      "version" in decoded &&
      typeof decoded.version === "string"
        ? decoded.version
        : undefined;
    if (version === undefined)
      return {
        ok: false,
        check: failureCheck(
          "version_unresolved",
          `${command} printed no LIEF version.`,
          LIEF_IMPORT_REMEDIATION,
          "missing_analysis_engine",
        ),
      };
    if (parseLiefVersion(version) === null)
      return {
        ok: false,
        check: failureCheck(
          "version_unresolved",
          `${command} reports an unparseable LIEF version: ${version}.`,
          LIEF_IMPORT_REMEDIATION,
          "config_drift",
        ),
      };
    if (!liefVersionSupported(version))
      return {
        ok: false,
        check: failureCheck(
          "version_unsupported",
          `${command} reports LIEF ${version}; this bridge targets ${LIEF_SUPPORTED_RANGE}.`,
          LIEF_IMPORT_REMEDIATION,
          "config_drift",
        ),
      };
    return { ok: true, version, command };
  } catch (cause: unknown) {
    return {
      ok: false,
      check: failureCheck(
        "import_failed",
        `${command} could not import LIEF: ${cause instanceof Error ? cause.message : String(cause)}.`,
        LIEF_IMPORT_REMEDIATION,
        "missing_analysis_engine",
      ),
    };
  }
};

/** Project the caller-supplied LIEF lane into the doctor without writing anything. */
export const inspectLiefProvider = async (
  environment: Readonly<NodeJS.ProcessEnv>,
): Promise<DoctorProviderInspection> => {
  const configured =
    environment[LIEF_COMMAND_ENV] !== undefined ||
    environment[LIEF_BRIDGE_DIR_ENV] !== undefined;
  const configuration = resolveLiefConfiguration(environment);
  if (!configuration.ok)
    return unavailable(configured, [
      {
        name: "configuration",
        ok: false,
        code: configuration.error.code,
        detail: `${configuration.error.reason} ${configuration.error.setting} selects the bridge.`,
        remediation: configuration.error.remediation,
        classification: configured ? "config_drift" : "missing_analysis_engine",
      },
    ]);
  const readiness = await probeInterpreter(configuration.value.command);
  if (!readiness.ok) return unavailable(configured, [readiness.check]);
  return {
    id: LIEF_PROVIDER_ID,
    configured: true,
    available: true,
    providerVersion: readiness.version,
    registrationEnvironment: Object.fromEntries(
      REGISTRATION_SETTINGS.flatMap((name) => {
        const setting = environment[name];
        return setting === undefined ? [] : [[name, setting]];
      }),
    ),
    checks: [
      {
        name: "installation",
        ok: true,
        code: null,
        detail: `${readiness.command} imports LIEF ${readiness.version}; the bridge script is ${configuration.value.bridgePath}.`,
        remediation: null,
        classification: "unknown",
        details: {
          executable: readiness.command,
          lief_version: readiness.version,
          bridge_script: configuration.value.bridgePath,
          bridge_script_name: LIEF_BRIDGE_FILE_NAME,
        },
      },
    ],
  };
};
