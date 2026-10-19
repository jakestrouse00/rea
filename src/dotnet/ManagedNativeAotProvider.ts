import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import {
  ArtifactFileCleanupFailure,
  assertArtifactReadActive,
  bindArtifactFileCleanup,
  artifactFileCancellationCause,
} from "../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { NativeAotPort } from "../application/nativeAot/NativeAotPort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import type {
  InspectNativeAotTypesInput,
  NativeAotArtifactInspection,
} from "../domain/managed/nativeAotArtifact.js";
import { inspectManagedNativeAotBytes } from "./ManagedNativeAotImage.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";

/** Bundled read-only NativeAOT structural reader identity. */
export const NATIVE_AOT_PROVIDER_IDENTITY = {
  id: "managed-nativeaot-inspection",
  name: "REA managed NativeAOT structural reader",
  version: "1",
} as const;
const OPERATION = "inspect_nativeaot_types";
const INPUT_BYTES = 256 * 1024 * 1024;
const OUTPUT_BYTES = 8 * 1024 * 1024;

const failureForPrimary = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
      cause,
    });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, {
      cause: artifactFileCancellationCause(cause),
    });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "limit")
    return new AnalysisResourceConstraintError(
      OPERATION,
      "file-size",
      cause.message,
      { maximum_input_bytes: INPUT_BYTES },
      {
        cause,
        remediationAction:
          "Select a stable artifact within the reported input byte allowance. Do not truncate required bytes; retrying the unchanged oversized input will fail again.",
      },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "path")
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["path"], reason: "invalid_format", message: cause.message },
    ]);
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
        cause,
      });
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(NATIVE_AOT_PROVIDER_IDENTITY.id, OPERATION, {
    cause,
    diagnostics: {
      path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};

const failureFor = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  const primary =
    cause instanceof ArtifactFileCleanupFailure &&
    cause.fileCleanupFailure.outcome.kind === "failed"
      ? failureForPrimary(cause.fileCleanupFailure.outcome.cause, path)
      : cause instanceof ArtifactFileCleanupFailure && signal?.aborted
        ? new AnalysisCancelledError(OPERATION, { cause: signal.reason })
        : failureForPrimary(cause, path);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    NATIVE_AOT_PROVIDER_IDENTITY.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation: OPERATION, cause },
  );
  const error = analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
  bindArtifactFileCleanup(cause, error);
  return error;
};

/** Read-only in-process NativeAOT artifact inspection; no subprocesses, no target execution. */
export class NativeAotProvider implements NativeAotPort {
  readonly identity = NATIVE_AOT_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ArtifactReaderFailure) ||
        cause.cleanup === undefined
      )
        throw cause;
      const error = new ProviderCleanupError(
        NATIVE_AOT_PROVIDER_IDENTITY.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: OPERATION },
      );
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  /** Read the complete artifact once and recover the documented structures. */
  async inspect(
    input: InspectNativeAotTypesInput,
    _options?: ExecutionOptions,
  ): Promise<Result<NativeAotArtifactInspection, AnalysisError>> {
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          INPUT_BYTES,
          _options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(_options?.signal);
        const report = {
          ...inspectManagedNativeAotBytes(snapshot.sha256, snapshot.bytes),
          artifact: {
            path: input.path,
            sha256: snapshot.sha256,
            byte_length: snapshot.bytes.length,
            format: "pe" as const,
          },
        };
        if (Buffer.byteLength(JSON.stringify(report), "utf8") > OUTPUT_BYTES)
          throw new AnalysisResourceConstraintError(
            OPERATION,
            "transport",
            `Complete NativeAOT structural inspection of ${input.path} exceeds the inline output budget; no partial success is returned.`,
            { maximum_output_bytes: OUTPUT_BYTES },
          );
        return ok(report);
      });
    } catch (cause: unknown) {
      return err(failureFor(cause, input.path, _options?.signal));
    }
  }
}
