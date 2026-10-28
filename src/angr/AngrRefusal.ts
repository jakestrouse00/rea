import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import {
  ANGR_BRIDGE_DIR_ENV,
  ANGR_PYTHON_ENV,
  ANGR_PROVIDER_ID,
  ANGR_REQUIRED_MINOR,
} from "../domain/angr/angrLimits.js";

const MAX_BRIDGE_MESSAGE = 512;

const bounded = (message: string): string =>
  message.length > MAX_BRIDGE_MESSAGE
    ? `${message.slice(0, MAX_BRIDGE_MESSAGE)}...`
    : message;

/** Project one bridge refusal code onto REA's error algebra. */
export const angrJobFailure = (
  operation: string,
  code: string,
  message: string,
): AnalysisError => {
  const reason = bounded(message);
  if (code === "missing_dependency" || code === "version_unsupported")
    return new AnalysisCapabilityUnavailableError(
      ANGR_PROVIDER_ID,
      operation,
      `${reason}. ${
        code === "missing_dependency"
          ? `Install angr ${ANGR_REQUIRED_MINOR}.x in the environment selected by ${ANGR_PYTHON_ENV}, or point ${ANGR_BRIDGE_DIR_ENV} and ${ANGR_PYTHON_ENV} elsewhere.`
          : `Install the pinned angr ${ANGR_REQUIRED_MINOR}.x release.`
      }`,
      { diagnostics: { bridge_error: code } },
    );
  if (
    code === "invalid_request" ||
    code === "unsupported_mode" ||
    code === "binary_unreadable" ||
    code === "loader_error" ||
    code === "entry_not_mapped"
  )
    return new AnalysisInputError(operation, {
      userMessage: reason,
      diagnostics: { bridge_error: code },
    });
  return new AnalysisProtocolError(
    `The angr bridge refused ${operation}: ${reason}`,
    { diagnostics: { bridge_error: code } },
  );
};
