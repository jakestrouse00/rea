import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";

import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  execFileOutput,
  execFileOutputFailure,
  ExecFileOutputCancelledError,
} from "../process/ExecFileOutput.js";
import {
  readIdeviceConfiguration,
  ideviceVersionProbeTimeoutMs,
  type IdeviceConfiguration,
  type IdeviceConfigurationFailure,
} from "./IdeviceConfiguration.js";
import {
  IDEVICE_COMMAND_REMEDIATION,
  IDEVICE_VERSION_PROBE_REMEDIATION,
  IDEVICE_VERIFIED_VERSION,
} from "./IdeviceRelease.js";

/**
 * Release CI and pip launchers print a pymobiledevice3 release string on
 * `--version`. Match a bare semver-ish release so versioned diagnostics stay
 * stable across launcher shims.
 */
const VERSION_LINE = /pymobiledevice3[ ]([0-9A-Za-z.-]+)[\r\n]*$/u;

/** One observed pymobiledevice3 launcher, identified by its probed release. */
export interface IdeviceInstallation {
  readonly configuration: IdeviceConfiguration;
  /** Canonical path of the probed launcher. */
  readonly executable: string;
  readonly version: string;
  /** Whether this release is one REA verified against real hardware. */
  readonly verified: boolean;
}

/** Why the selected installation cannot be used. */
export interface IdeviceReadinessFailure {
  readonly code:
    | IdeviceConfigurationFailure["code"]
    | "executable_missing"
    | "version_unresolved";
  readonly reason: string;
  readonly diagnostics: Readonly<Record<string, JsonValue>>;
}

export interface IdeviceInstallationOptions {
  readonly platform?: NodeJS.Platform;
  readonly signal?: AbortSignal;
}

const message = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const failure = (
  code: IdeviceReadinessFailure["code"],
  reason: string,
  diagnostics: Readonly<Record<string, JsonValue>>,
): Result<never, IdeviceReadinessFailure> => err({ code, reason, diagnostics });

/**
 * Resolve, version-probe and return the configured pymobiledevice3 launcher.
 * The probe runs the launcher script itself, so a hanging launcher cannot
 * hang the caller beyond the probe deadline.
 */
export const inspectIdeviceInstallation = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: IdeviceInstallationOptions = {},
): Promise<Result<IdeviceInstallation, IdeviceReadinessFailure>> => {
  const configuration = readIdeviceConfiguration(environment, options.platform);
  if (!configuration.ok)
    return failure(configuration.error.code, configuration.error.reason, {
      configured: configuration.error.code !== "not_configured",
      ...(configuration.error.setting === null
        ? {}
        : { setting: configuration.error.setting }),
    });
  const { command } = configuration.value;

  let executable: string;
  try {
    executable = await realpath(command);
    await access(executable, constants.X_OK);
    if (!(await stat(executable)).isFile())
      return failure(
        "executable_missing",
        `REA_IPHONE_PMD3_COMMAND is not a regular file: ${command}. ${IDEVICE_COMMAND_REMEDIATION}`,
        { command },
      );
  } catch (cause: unknown) {
    return failure(
      "executable_missing",
      `Cannot execute REA_IPHONE_PMD3_COMMAND ${command}: ${message(cause)}. ${IDEVICE_COMMAND_REMEDIATION}`,
      { command },
    );
  }

  let stdout: string;
  try {
    ({ stdout } = await execFileOutput(executable, ["--version"], {
      timeout: ideviceVersionProbeTimeoutMs,
      maxBuffer: 64 * 1024,
      stopSignal: "SIGTERM",
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    }));
  } catch (cause: unknown) {
    // A caller abort is cancellation, never an unresolved release.
    if (cause instanceof ExecFileOutputCancelledError) throw cause;
    const output = execFileOutputFailure(cause);
    return failure(
      "version_unresolved",
      `${executable} --version failed: ${output?.stderr.trim() || message(cause)}. ${IDEVICE_VERSION_PROBE_REMEDIATION}`,
      {
        command,
        executable,
        exit_code: typeof output?.code === "number" ? output.code : null,
        signal: output?.signal ?? null,
        killed: output?.killed ?? false,
        output_truncated: output?.outputTruncated ?? false,
        deadline_ms: ideviceVersionProbeTimeoutMs,
      },
    );
  }
  const version = VERSION_LINE.exec(stdout)?.[1];
  if (version === undefined)
    return failure(
      "version_unresolved",
      `${executable} --version printed no recognizable pymobiledevice3 release. ${IDEVICE_VERSION_PROBE_REMEDIATION}`,
      { command, executable, stdout: stdout.slice(0, 256) },
    );

  return ok({
    configuration: configuration.value,
    executable,
    version,
    verified: version === IDEVICE_VERIFIED_VERSION,
  });
};
