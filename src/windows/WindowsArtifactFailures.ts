import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { artifactFileCancellationCause } from "../artifacts/ArtifactFileOperation.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  MinidumpFormatFailure,
  MinidumpResourceFailure,
} from "./WindowsMinidump.js";

/** One shared mapping from bounded read + parser failures to typed errors. */
export const windowsArtifactFailure = (
  operation: string,
  providerId: string,
  cause: unknown,
  path: string,
  maximumInputBytes: number,
): AnalysisError => {
  if (cause instanceof MinidumpFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(operation, path, cause.message, {
          cause,
        })
      : new AnalysisInputError(operation, { cause }, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: `Selected artifact ${path}: ${cause.message}`,
          },
        ]);
  if (cause instanceof MinidumpResourceFailure)
    return new AnalysisResourceConstraintError(
      operation,
      "memory",
      `Selected artifact ${path}: ${cause.message}`,
      { boundary: cause.boundary, maximum_entries: cause.maximum_entries },
      { cause },
    );
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "integrity")
      return new AnalysisArtifactChangedError(operation, path, cause.message, {
        cause,
      });
    if (cause.reason === "cancelled")
      return new AnalysisCancelledError(operation, {
        cause: artifactFileCancellationCause(cause),
      });
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        operation,
        "file-size",
        cause.message,
        { maximum_input_bytes: maximumInputBytes },
        {
          cause,
          remediationAction:
            "Select a suitable stable artifact within the reported input byte allowance. Do not truncate required bytes; retrying the unchanged oversized input will fail again.",
        },
      );
    if (cause.reason === "path")
      return new AnalysisInputError(operation, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(operation, path, cause.code, {
        cause,
      });
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(operation, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(providerId, operation, {
    cause,
    diagnostics: {
      path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};
