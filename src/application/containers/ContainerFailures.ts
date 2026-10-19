import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { CONTAINER_PROVIDER_IDENTITY } from "../../domain/containers/containerIdentity.js";
import { ContainerFormatError } from "../../domain/containers/containerFormatError.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { RegularFileCleanupFailure } from "../../filesystem/OwnedRegularFile.js";
import {
  NonRegularFileReadError,
  RegularFileChangedError,
  RegularFileOperationCancelled,
} from "../../filesystem/RegularFile.js";
import { RegularFileCapacityError } from "../../filesystem/readStableFileBytes.js";
import { StableFileHashFailure } from "../../filesystem/StableFileHash.js";

/** Type one physical container-inspection failure without recomposing meaning. */
const cleanupIdentifier = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

export const containerFailure = (
  cause: unknown,
  path: string,
  phase: string,
  signal?: AbortSignal,
): AnalysisError => {
  const operation = phase;
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof RegularFileCleanupFailure) {
    // The failed descriptor close owns its exact resource; the primary
    // outcome stays available through the error for later retry mapping.
    return new ProviderCleanupError(
      CONTAINER_PROVIDER_IDENTITY.id,
      [cause.path],
      { reason: cleanupIdentifier(cause.cleanupCause) },
      { operation, cause },
    );
  }
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "integrity")
      return new AnalysisArtifactChangedError(operation, path, cause.message, {
        cause,
      });
    if (cause.reason === "cancelled")
      return new AnalysisCancelledError(operation, { cause });
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        operation,
        "file-size",
        cause.message,
        null,
        { cause },
      );
    if (cause.reason === "io" && cause.cause !== undefined)
      return containerFailure(cause.cause, path, phase, signal);
    if (cause.reason === "unavailable")
      return new AnalysisUnsupportedTargetError(
        operation,
        path,
        cause.message,
        {
          cause,
        },
      );
    return new AnalysisInputError(operation, { cause }, [
      {
        path: ["path"],
        reason: "invalid_format",
        message: cause.message,
      },
    ]);
  }
  if (cause instanceof ContainerFormatError) {
    if (cause.kind === "limit")
      return new AnalysisResourceConstraintError(
        operation,
        "file-size",
        cause.message,
        null,
        { cause },
      );
    if (cause.kind === "unsupported")
      return new AnalysisUnsupportedTargetError(
        operation,
        path,
        cause.message,
        {
          cause,
        },
      );
    return new AnalysisInputError(operation, { cause }, [
      {
        path: ["path"],
        reason: "invalid_format",
        message: cause.message,
      },
    ]);
  }
  if (cause instanceof RegularFileCapacityError)
    return new AnalysisResourceConstraintError(
      operation,
      "file-size",
      cause.message,
      {
        maximum_bytes: cause.maximumBytes,
        observed_bytes: cause.observedBytes.toString(),
      },
      { cause },
    );
  if (cause instanceof RegularFileChangedError)
    return new AnalysisArtifactChangedError(operation, path, cause.message, {
      cause,
    });
  if (cause instanceof NonRegularFileReadError)
    return new AnalysisInputError(operation, { cause }, [
      {
        path: ["path"],
        reason: "invalid_value",
        message: cause.message,
      },
    ]);
  if (cause instanceof RegularFileOperationCancelled || signal?.aborted)
    return new AnalysisCancelledError(operation, {
      cause:
        cause instanceof RegularFileOperationCancelled
          ? cause.reason
          : signal?.reason,
    });
  if (cause instanceof StableFileHashFailure)
    return containerFailure(cause.cause, path, phase, signal);
  if (cause instanceof Error && cause.name === "AbortError")
    return new AnalysisCancelledError(operation, { cause });
  if (cause instanceof Error && "code" in cause) {
    const code = String(cause.code);
    if (code === "EACCES" || code === "EPERM")
      return new AnalysisAccessDeniedError(operation, path, code, { cause });
    if (
      code === "ENOENT" ||
      code === "ENOTDIR" ||
      code === "ELOOP" ||
      code === "ENAMETOOLONG"
    )
      return new AnalysisInputError(operation, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected container file could not be read (${code}): ${path}`,
        },
      ]);
  }
  return new ProviderAdapterError(CONTAINER_PROVIDER_IDENTITY.id, operation, {
    cause,
    diagnostics: {
      phase,
      path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};
