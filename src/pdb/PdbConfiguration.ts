import { isAbsolute } from "node:path";

import { err, ok, type Result } from "../domain/result.js";

/** Caller-selected BYO llvm-pdbutil and measured bounded-output policy. */
export interface PdbConfiguration {
  /** Caller-selected executable path, preserved exactly as configured. */
  readonly command: string;
  /** Deadline for one bounded `llvm-pdbutil dump` or `--version` run. */
  readonly dumpTimeoutMs: number;
  readonly versionTimeoutMs: number;
  /**
   * Bounded stdout+stderr budget; a run that exceeds it fails typed rather
   * than partially, because truncated CodeView section text cannot be
   * honestly reported as complete.
   */
  readonly maximumOutputBytes: number;
}

/** Default dump deadline: llvm-pdbutil dumps finish in seconds at this size. */
const DEFAULT_DUMP_TIMEOUT_MS = 120_000;
const DEFAULT_VERSION_TIMEOUT_MS = 10_000;
const DEFAULT_MAXIMUM_OUTPUT_BYTES = 128 * 1024 * 1024;

/** Why the configured environment cannot select an llvm-pdbutil executable. */
export interface PdbConfigurationFailure {
  readonly code: "not_configured" | "invalid_path";
  readonly reason: string;
  readonly setting: string;
}

/** Parse the llvm-pdbutil settings without touching the filesystem or process. */
export const readPdbConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv>,
): Result<PdbConfiguration, PdbConfigurationFailure> => {
  const command = environment.REA_LLVM_PDBUTIL_COMMAND;
  const failure = (
    code: PdbConfigurationFailure["code"],
    reason: string,
  ): Result<never, PdbConfigurationFailure> =>
    err({ code, reason, setting: "REA_LLVM_PDBUTIL_COMMAND" });
  if (command === undefined || command.length === 0)
    return failure("not_configured", "REA_LLVM_PDBUTIL_COMMAND is not set.");
  if (!isAbsolute(command))
    return failure(
      "invalid_path",
      `REA_LLVM_PDBUTIL_COMMAND must be an absolute path; received ${command}.`,
    );
  return ok({
    command,
    dumpTimeoutMs: DEFAULT_DUMP_TIMEOUT_MS,
    versionTimeoutMs: DEFAULT_VERSION_TIMEOUT_MS,
    maximumOutputBytes: DEFAULT_MAXIMUM_OUTPUT_BYTES,
  });
};
