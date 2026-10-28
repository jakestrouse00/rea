import { AnalysisInputError } from "../../domain/analysisErrorCore.js";

/** A session ID that names no open Frida session owned by this process. */
export const unknownFridaSession = (
  operation: string,
  sessionId: string,
): AnalysisInputError =>
  new AnalysisInputError(operation, undefined, [
    {
      path: ["session_id"],
      reason: "invalid_value",
      message: `No open Frida session ${sessionId}; start one with start_frida_session.`,
    },
  ]);

/** A script ID that names no loaded script in the selected session. */
export const unknownFridaScript = (
  operation: string,
  scriptId: string,
): AnalysisInputError =>
  new AnalysisInputError(operation, undefined, [
    {
      path: ["script_id"],
      reason: "invalid_value",
      message: `No loaded Frida script ${scriptId} in this session.`,
    },
  ]);

/**
 * REA owns a script handle only while the load that created it is retained.
 * A script_id that was unloaded, or whose session closed or detached, names no
 * live owner, so its identity alone cannot authorize another target call.
 */
export const unownedFridaScript = (
  operation: string,
  scriptId: string,
): AnalysisInputError =>
  new AnalysisInputError(operation, undefined, [
    {
      path: ["script_id"],
      reason: "invalid_value",
      message: `Frida script ${scriptId} is not owned by this session: it was unloaded, released, or its session closed. A script_id alone does not establish ownership after unload; load the script again to invoke its exports.`,
    },
  ]);
