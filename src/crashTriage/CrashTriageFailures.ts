import { createHash } from "node:crypto";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { CRASH_TRIAGE_PROVIDER } from "../domain/crashTriage/crashReport.js";
import { CRASH_TRIAGE_MAX_DEDUP_GROUPS } from "../domain/crashTriage/fuzzingCampaign.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { CrashTriageStoreFailure } from "./CrashTriageStore.js";

/** Whether a caller already cancelled the operation. */
export const crashTriageAborted = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;

export const crashTriageCancelled = (
  operation: string,
  signal: AbortSignal | undefined,
): AnalysisCancelledError =>
  new AnalysisCancelledError(operation, { cause: signal?.reason });

/** A campaign id this server never issued cannot be looked up elsewhere. */
export const unknownCampaign = (
  operation: string,
  campaignId: string,
): AnalysisError =>
  new AnalysisInputError(
    operation,
    {
      userMessage: `No campaign ${campaignId} exists in this REA server process. Campaign identity is server-lifetime; register a campaign before reading it.`,
    },
    [{ path: ["campaign_id"], reason: "invalid_value" }],
  );

/** Clamp a caller's group bound into the store's declared listing range. */
export const boundedDedupLimit = (requested: number): number =>
  Math.min(Math.max(Math.trunc(requested), 1), CRASH_TRIAGE_MAX_DEDUP_GROUPS);

/** Digest and size of a report body REA is about to retain. */
export const reportBytes = (
  body: string,
): { readonly sha256: string; readonly bytes: number } => {
  const encoded = Buffer.from(body, "utf8");
  return {
    sha256: createHash("sha256").update(encoded).digest("hex"),
    bytes: encoded.byteLength,
  };
};

/** Project one store failure onto the provider-neutral error algebra. */
export const storeFailure = (
  operation: string,
  cause: unknown,
): AnalysisError => {
  if (cause instanceof CrashTriageStoreFailure)
    return cause.reason === "unsupported_schema"
      ? new AnalysisCapabilityUnavailableError(
          CRASH_TRIAGE_PROVIDER.id,
          operation,
          cause.message,
          {
            cause,
            userMessage: cause.message,
            remediationAction:
              "This REA server owns its crash-triage store for its own lifetime. Restart the server to allocate a fresh store instead of reading a newer schema.",
            diagnostics: { ...cause.diagnostics },
          },
        )
      : new ProviderAdapterError(CRASH_TRIAGE_PROVIDER.id, operation, {
          cause,
          userMessage: cause.message,
          diagnostics: { store_failure: cause.reason, ...cause.diagnostics },
        });
  return new ProviderAdapterError(CRASH_TRIAGE_PROVIDER.id, operation, {
    cause,
    userMessage: `The crash-triage store failed during ${operation}: ${
      cause instanceof Error ? cause.message : String(cause)
    }`,
  });
};
