import { createEvidence, type Evidence } from "../evidence.js";
import type {
  AsarIntegrityReport,
  InspectAsarIntegrityInput,
} from "./asarIntegrity.js";

/** Preserve the same validated ASAR facts on success and incomplete finalization. */
export const createAsarIntegrityEvidence = (
  input: InspectAsarIntegrityInput,
  value: AsarIntegrityReport,
  provider: Evidence["provider"],
): Evidence =>
  createEvidence(
    {
      path: value.resolved_path,
      sha256: value.sha256,
      format: "asar",
    },
    provider,
    {
      operation: "inspect_asar_integrity",
      parameters: input,
      result: value,
      confidence: "observed",
      limitations: value.limitations,
      locations: [
        { kind: "artifact-path" as const, path: value.path },
        ...(value.resolved_path === value.path
          ? []
          : [{ kind: "artifact-path" as const, path: value.resolved_path }]),
      ],
    },
  );
