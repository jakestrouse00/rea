import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { PDB_COMMAND_REMEDIATION, PDB_PROVIDER_ID } from "./PdbRelease.js";

/** The PDB lane's typed refusals carry the caller-fixable reason verbatim. */
export const pdbUnavailable = (
  operation: string,
  reason: string,
  remediation: string = PDB_COMMAND_REMEDIATION,
): AnalysisCapabilityUnavailableError =>
  new AnalysisCapabilityUnavailableError(PDB_PROVIDER_ID, operation, reason, {
    userMessage: reason,
    remediationAction: remediation,
  });
