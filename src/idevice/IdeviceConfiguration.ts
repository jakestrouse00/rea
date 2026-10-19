import { isAbsolute } from "node:path";

import { err, ok, type Result } from "../domain/result.js";
import { providerStartupTimeoutSchema } from "../config/providerStartupTimeout.js";
import {
  IDEVICE_COMMAND_REMEDIATION,
  IDEVICE_UNSUPPORTED_HOST_REMEDIATION,
} from "./IdeviceRelease.js";

/** One bounded pmd3 probe or one-shot device command. */
const DEFAULT_OPERATION_TIMEOUT_MS = 60_000;

/** `pymobiledevice3 --version` exits before touching usbmuxd. */
const VERSION_PROBE_TIMEOUT_MS = 20_000;

/** Caller-selected pymobiledevice3 launch command and REA-owned bounds. */
export interface IdeviceConfiguration {
  /** Caller-selected launcher script path, preserved exactly as configured. */
  readonly command: string;
  /** Deadline for one one-shot device command, including device probes. */
  readonly operationTimeoutMs: number;
}

/** Why the configured environment cannot select a pymobiledevice3 command. */
export interface IdeviceConfigurationFailure {
  readonly code: "not_configured" | "open_options_invalid" | "unsupported_host";
  readonly reason: string;
  readonly setting: string | null;
}

const failure = (
  code: IdeviceConfigurationFailure["code"],
  reason: string,
  setting: string | null = null,
): Result<never, IdeviceConfigurationFailure> => err({ code, reason, setting });

/**
 * Parse the iOS device settings without touching the filesystem or running
 * the launcher. The macOS lane is the verified scope; other hosts refuse
 * plainly instead of pretending parity.
 */
export const readIdeviceConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): Result<IdeviceConfiguration, IdeviceConfigurationFailure> => {
  // Host support first: an unset lane on an unsupported host must classify as
  // unsupported_host, not as a missing setting.
  if (platform !== "darwin")
    return failure("unsupported_host", IDEVICE_UNSUPPORTED_HOST_REMEDIATION);
  const command = environment.REA_IPHONE_PMD3_COMMAND;
  if (command === undefined || command.length === 0)
    return failure("not_configured", IDEVICE_COMMAND_REMEDIATION);
  if (!isAbsolute(command))
    return failure(
      "open_options_invalid",
      `REA_IPHONE_PMD3_COMMAND must be an absolute path; received ${command}. ${IDEVICE_COMMAND_REMEDIATION}`,
      "REA_IPHONE_PMD3_COMMAND",
    );

  const rawTimeout = environment.REA_IDEVICE_TIMEOUT_MS;
  if (rawTimeout === undefined)
    return ok({ command, operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS });
  const timeout = providerStartupTimeoutSchema.safeParse(rawTimeout);
  if (!timeout.success)
    return failure(
      "open_options_invalid",
      `REA_IDEVICE_TIMEOUT_MS must be a decimal millisecond count from 1 to 2147483647; received ${String(rawTimeout)}.`,
      "REA_IDEVICE_TIMEOUT_MS",
    );
  return ok({ command, operationTimeoutMs: timeout.data });
};

/** Probe deadline; a launcher that hangs must not hang doctor. */
export const ideviceVersionProbeTimeoutMs = VERSION_PROBE_TIMEOUT_MS;
