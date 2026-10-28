import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { stat } from "node:fs/promises";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";

/** The digest REA computed for the artifact the job is allowed to analyse. */
export interface AngrTargetDigest {
  readonly sha256: string;
  readonly size: number;
}

/**
 * Digest exactly the bytes at the caller's path. A caller-selected path that
 * is not one readable regular file is an input refusal, not a provider fault.
 */
export const digestAngrTarget = async (
  operation: string,
  path: string,
  signal: AbortSignal | undefined,
): Promise<Result<AngrTargetDigest, AnalysisError>> => {
  try {
    const facts = await stat(path);
    if (!facts.isFile())
      return err(
        new AnalysisInputError(operation, {
          userMessage: `The selected artifact is not a regular file: ${path}`,
        }),
      );
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code ?? null;
    return err(
      new AnalysisInputError(operation, {
        userMessage:
          code === "EACCES" || code === "EPERM"
            ? `The selected artifact is not readable: ${path}`
            : `The selected artifact was not found: ${path}`,
        diagnostics: code === null ? {} : { filesystem_error: code },
        cause,
      }),
    );
  }
  const hash = createHash("sha256");
  let size = 0;
  try {
    for await (const raw of createReadStream(path, {
      highWaterMark: 1 << 20,
    })) {
      if (signal?.aborted === true)
        return err(
          new AnalysisCancelledError(operation, { cause: signal.reason }),
        );
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as Uint8Array);
      size += chunk.byteLength;
      hash.update(chunk);
    }
  } catch (cause: unknown) {
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    return err(
      new AnalysisInputError(operation, {
        userMessage: `The selected artifact could not be read whole: ${path}`,
        cause,
      }),
    );
  }
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  return ok({ sha256: hash.digest("hex"), size });
};
