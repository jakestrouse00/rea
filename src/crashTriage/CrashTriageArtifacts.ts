import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, stat } from "node:fs/promises";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import type { CampaignArtifact } from "../domain/crashTriage/fuzzingCampaign.js";
import { CRASH_TRIAGE_MAX_ARTIFACT_BYTES } from "../domain/crashTriage/fuzzingCampaign.js";
import { err, ok, type Result } from "../domain/result.js";

/** Observed identity and size of one caller-selected file. */
export interface ObservedFile {
  readonly bytes: number;
  readonly sha256: string;
}

const cancelled = (
  operation: string,
  signal: AbortSignal,
): AnalysisCancelledError =>
  new AnalysisCancelledError(operation, { cause: signal.reason });

const hashStream = async (
  path: string,
  operation: string,
  signal: AbortSignal | undefined,
): Promise<string> => {
  const hash = createHash("sha256");
  const stream = createReadStream(path);
  try {
    for await (const chunk of stream) {
      if (signal?.aborted === true) {
        stream.destroy();
        throw cancelled(operation, signal);
      }
      hash.update(chunk as Buffer);
    }
  } finally {
    stream.destroy();
  }
  return hash.digest("hex");
};

/**
 * Digest one regular file without following symbolic links.
 *
 * The caller's path is never rewritten and its digest is computed from the
 * bytes on disk, so a target or seed that changed during registration is
 * reported at its current identity rather than an assumed one.
 */
export const digestCampaignArtifact = async (
  path: string,
  operation: string,
  options: {
    readonly label: "target" | "seed";
    readonly signal?: AbortSignal;
  },
): Promise<Result<CampaignArtifact, AnalysisError>> => {
  try {
    if (options.signal?.aborted === true)
      throw cancelled(operation, options.signal);
    const link = await lstat(path);
    if (link.isSymbolicLink() || !link.isFile())
      return err(
        new AnalysisInputError(operation, {
          userMessage: `The campaign ${options.label} is not a regular file: ${path}`,
        }),
      );
    if (link.size > CRASH_TRIAGE_MAX_ARTIFACT_BYTES)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `The campaign ${options.label} is ${String(link.size)} bytes, above the ${String(CRASH_TRIAGE_MAX_ARTIFACT_BYTES)}-byte digest budget`,
          {
            max_artifact_bytes: CRASH_TRIAGE_MAX_ARTIFACT_BYTES,
            artifact_bytes: link.size,
            label: options.label,
          },
          {
            remediationAction:
              "Select a smaller target or seed; the artifact digest budget has no runtime override.",
          },
        ),
      );
    const sha256 = await hashStream(path, operation, options.signal);
    return ok({ path, sha256, bytes: link.size });
  } catch (cause: unknown) {
    if (cause instanceof Error && "_tag" in cause)
      return err(cause as AnalysisError);
    return err(
      new AnalysisInputError(operation, {
        cause,
        userMessage: `The campaign ${options.label} could not be read: ${path}`,
      }),
    );
  }
};

/**
 * Observe the digest and size of a file REA caused to be written.
 *
 * Returns null when the path is not a regular file, so a minimizer that
 * reported success without writing its artifact is never reported as having
 * produced one.
 */
export const observeWrittenFile = async (
  path: string,
  operation: string,
  signal: AbortSignal | undefined,
): Promise<ObservedFile | null> => {
  try {
    const observed = await stat(path);
    if (!observed.isFile()) return null;
    if (observed.size > CRASH_TRIAGE_MAX_ARTIFACT_BYTES) return null;
    const sha256 = await hashStream(path, operation, signal);
    return { bytes: observed.size, sha256 };
  } catch {
    return null;
  }
};
