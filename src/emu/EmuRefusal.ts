import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { EMU_PROVIDER_ID } from "../domain/emu/emuLimits.js";

const MAX_BRIDGE_MESSAGE = 512;

const bounded = (message: string): string =>
  message.length > MAX_BRIDGE_MESSAGE
    ? `${message.slice(0, MAX_BRIDGE_MESSAGE)}...`
    : message;

/** Project one bridge refusal code onto REA's error algebra. */
export const bridgeJobFailure = (
  operation: string,
  code: string,
  message: string,
): AnalysisError => {
  const reason = bounded(message);
  if (code === "missing_dependency" || code === "version_unsupported")
    return new AnalysisCapabilityUnavailableError(
      EMU_PROVIDER_ID,
      operation,
      `${reason}. ${
        code === "missing_dependency"
          ? "Install Unicorn 2.1.x and Keystone in the environment selected by the interpreter, or point the interpreter elsewhere."
          : "Install the pinned Unicorn 2.1.x release."
      }`,
      { diagnostics: { bridge_error: code } },
    );
  if (code === "invalid_request" || code === "unsupported_mode")
    return new AnalysisInputError(operation, {
      userMessage: reason,
      diagnostics: { bridge_error: code },
    });
  return new AnalysisProtocolError(
    `The Unicorn bridge refused ${operation}: ${reason}`,
    { diagnostics: { bridge_error: code } },
  );
};
