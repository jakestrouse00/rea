import { createHash } from "node:crypto";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  isSelectedRegularFileError,
  openRegularFile,
} from "../filesystem/RegularFile.js";

/** Bytes REA selected, with the facts Evidence reports instead of the bytes. */
export interface CodeBytes {
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly path: string | null;
  readonly offset: number | null;
}

export const sha256Hex = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

export const hexAddress = (value: bigint): string => `0x${value.toString(16)}`;

/** Place one offset inside the caller's code window, refusing an overflow. */
export const addressAt = (
  operation: string,
  base: string,
  offset: number,
  length: number,
): Result<string, AnalysisError> => {
  if (offset >= length)
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["entry_offset"],
          reason: "invalid_value",
          message: `entry_offset ${String(offset)} lies past the ${String(length)} admitted code bytes`,
        },
      ]),
    );
  const entry = BigInt(base) + BigInt(offset);
  if (entry > 0xffff_ffff_ffff_ffffn)
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["code_base"],
          reason: "invalid_value",
          message:
            "code_base plus entry_offset exceeds the 64-bit address space",
        },
      ]),
    );
  return ok(hexAddress(entry));
};

/** Read one bounded code slice through the shared regular-file admission. */
export const readCodeSlice = async (
  operation: string,
  path: string,
  offset: number,
  length: number,
  signal: AbortSignal | undefined,
): Promise<Result<CodeBytes, AnalysisError>> => {
  let descriptor;
  try {
    descriptor = await openRegularFile(path, { symlinks: "follow", signal });
  } catch (cause: unknown) {
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    return err(
      new AnalysisInputError(operation, {
        cause,
        userMessage: isSelectedRegularFileError(cause)
          ? `The selected code file could not be read: ${path}`
          : `The selected code file could not be admitted: ${path}`,
      }),
    );
  }
  try {
    const size = descriptor.initial.size;
    if (offset + length > size)
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["source", "length"],
            reason: "invalid_value",
            message: `The ${String(length)}-byte window at offset ${String(offset)} exceeds the ${String(size)}-byte file`,
          },
        ]),
      );
    const bytes = Buffer.alloc(length);
    const read = await descriptor.handle.read(bytes, 0, length, offset);
    if (read.bytesRead !== length)
      return err(
        new AnalysisInputError(operation, {
          userMessage: `The selected code file returned ${String(read.bytesRead)} of ${String(length)} requested bytes: ${path}`,
        }),
      );
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    return ok({ bytes, sha256: sha256Hex(bytes), path, offset });
  } catch (cause: unknown) {
    return err(
      new AnalysisInputError(operation, {
        cause,
        userMessage: `The selected code file could not be read: ${path}`,
      }),
    );
  } finally {
    await descriptor.handle.close().catch(() => undefined);
  }
};
