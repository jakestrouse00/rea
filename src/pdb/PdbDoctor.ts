import { stat } from "node:fs/promises";

import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import { execFileOutput } from "../process/ExecFileOutput.js";
import {
  readPdbConfiguration,
  type PdbConfiguration,
} from "./PdbConfiguration.js";
import {
  PDB_COMMAND_REMEDIATION,
  PDB_PROVIDER_ID,
  PDB_VERSION_PROBE_REMEDIATION,
} from "./PdbRelease.js";

/** Settings a registration may carry; only those the caller set explicitly. */
const REGISTRATION_SETTINGS = ["REA_LLVM_PDBUTIL_COMMAND"] as const;

/** `llvm-pdbutil --version` exits before touching an input; a small budget. */
const VERSION_PROBE_MAX_OUTPUT_BYTES = 64 * 1024;

/** One unsuccessful readiness fact: an exact code with the caller's fix. */
const failureCheck = (
  code: string,
  detail: string,
  classification: "missing_analysis_engine" | "config_drift",
): DoctorProviderCheck => ({
  name: "installation",
  ok: false,
  code,
  detail,
  remediation: PDB_COMMAND_REMEDIATION,
  classification,
});

const unavailable = (
  configured: boolean,
  checks: readonly DoctorProviderCheck[],
): DoctorProviderInspection => ({
  id: PDB_PROVIDER_ID,
  configured,
  available: false,
  providerVersion: null,
  registrationEnvironment: {},
  checks,
});

/** Why the selected llvm-pdbutil installation cannot be used. */
type PdbReadiness =
  | {
      readonly ok: true;
      readonly version: string | null;
      readonly command: string;
    }
  | { readonly ok: false; readonly check: DoctorProviderCheck };

const probeInstallation = async (
  configuration: PdbConfiguration,
): Promise<PdbReadiness> => {
  let stats;
  try {
    stats = await stat(configuration.command);
  } catch (cause: unknown) {
    return {
      ok: false,
      check: failureCheck(
        "executable_missing",
        `REA_LLVM_PDBUTIL_COMMAND does not exist: ${configuration.command}.`,
        "config_drift",
      ),
    };
  }
  if (!stats.isFile())
    return {
      ok: false,
      check: failureCheck(
        "invalid_path",
        `REA_LLVM_PDBUTIL_COMMAND is not a regular file: ${configuration.command}.`,
        "config_drift",
      ),
    };
  try {
    const output = await execFileOutput(configuration.command, ["--version"], {
      timeout: configuration.versionTimeoutMs,
      maxBuffer: VERSION_PROBE_MAX_OUTPUT_BYTES,
    });
    const firstLine = output.stdout.split(/\r?\n/u, 1)[0] ?? "";
    return {
      ok: true,
      version: firstLine.length > 0 ? firstLine : null,
      command: configuration.command,
    };
  } catch (cause: unknown) {
    return {
      ok: false,
      check: {
        name: "installation",
        ok: false,
        code: "version_unresolved",
        detail: `llvm-pdbutil --version failed for ${configuration.command}: ${cause instanceof Error ? cause.message : String(cause)}.`,
        remediation: PDB_VERSION_PROBE_REMEDIATION,
        classification: "config_drift",
      },
    };
  }
};

/** Project the BYO llvm-pdbutil lane into the doctor contract without writing anything. */
export const inspectLlvmPdbutil = async (
  environment: Readonly<NodeJS.ProcessEnv>,
): Promise<DoctorProviderInspection> => {
  const configuration = readPdbConfiguration(environment);
  const configured = environment.REA_LLVM_PDBUTIL_COMMAND !== undefined;
  if (!configuration.ok)
    return unavailable(configured, [
      {
        name: "configuration",
        ok: false,
        code: configuration.error.code,
        detail: configuration.error.reason,
        remediation: PDB_COMMAND_REMEDIATION,
        classification: configured ? "config_drift" : "missing_analysis_engine",
      },
    ]);
  const readiness = await probeInstallation(configuration.value);
  if (!readiness.ok) return unavailable(configured, [readiness.check]);
  return {
    id: PDB_PROVIDER_ID,
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
        detail:
          readiness.version === null
            ? `${readiness.command} is present but printed an unreadable version banner.`
            : `${readiness.command} reports ${readiness.version}.`,
        remediation:
          readiness.version === null ? PDB_VERSION_PROBE_REMEDIATION : null,
        classification: "unknown",
        details: { executable: readiness.command, version: readiness.version },
      },
    ],
  };
};
