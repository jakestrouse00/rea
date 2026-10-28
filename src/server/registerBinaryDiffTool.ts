import { resolvePairedEvidenceRequest } from "../application/EvidenceInputResolver.js";
import type { BindiffPort } from "../application/bindiff/BindiffPort.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { BinarySessionPort } from "../application/binary/BinarySessionPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import { BINARY_DIFF_PROVIDER } from "../domain/comparisonEvidenceIdentity.js";
import { createEvidence } from "../domain/evidence.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import { readEvidence } from "../domain/evidenceValidation.js";
import { recordDerivedEvidence } from "./recordDerivedEvidence.js";
import { runAdmittedToolOperation } from "./admittedToolOperation.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { withAdmittedAnalysis } from "./analysisAdmission.js";

interface ArtifactSubject {
  readonly path: string;
  readonly sha256: string;
}

const artifactSubject = (
  input: unknown,
  path: readonly (string | number)[],
): Result<ArtifactSubject, AnalysisInputError> => {
  const parsed = readEvidence(input);
  if (!parsed.ok)
    return err(
      new AnalysisInputError("diff_binaries", { cause: parsed.error }, [
        {
          path,
          reason: "invalid_value",
          message: "The selected Evidence record is not authenticated",
        },
      ]),
    );
  const evidence = parsed.value;
  if (evidence.operation !== "inspect_artifact")
    return err(
      new AnalysisInputError("diff_binaries", {}, [
        {
          path,
          reason: "invalid_value",
          message: `diff_binaries requires inspect_artifact Evidence; the selected record is ${evidence.operation}`,
          expected: "inspect_artifact",
        },
      ]),
    );
  if (evidence.subject === null)
    return err(
      new AnalysisInputError("diff_binaries", {}, [
        {
          path,
          reason: "invalid_value",
          message: "diff_binaries requires artifact-bound Evidence",
        },
      ]),
    );
  return ok({
    path: evidence.subject.local_path,
    sha256: evidence.subject.digest.sha256,
  });
};

/** Register the provider-backed binary comparison over retained artifacts. */
export const registerBinaryDiffTool = (
  server: EvidenceMcpServer,
  session: BinarySessionPort,
  contract: ReturnType<typeof toolContract<"diff_binaries">>,
  provider: BindiffPort,
): void => {
  const admission = withAdmittedAnalysis({ kind: "session", session });
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) =>
      runAdmittedToolOperation(
        server,
        admission,
        contract.name,
        context.mcpReq.signal,
        async () => {
          const resolved = resolvePairedEvidenceRequest(
            input,
            session.evidenceForAnalysis.bind(session),
          );
          if (!resolved.ok)
            return server.delivery.toCallToolResult(resolved, contract);
          const left = artifactSubject(resolved.value.left, ["left"]);
          if (!left.ok) return server.delivery.toCallToolResult(left, contract);
          const right = artifactSubject(resolved.value.right, ["right"]);
          if (!right.ok)
            return server.delivery.toCallToolResult(right, contract);
          const diffed = await provider.diff(
            {
              primaryPath: left.value.path,
              secondaryPath: right.value.path,
              primarySha256: left.value.sha256,
              secondarySha256: right.value.sha256,
              maxMatches: input.max_matches,
            },
            { signal: context.mcpReq.signal },
          );
          if (!diffed.ok)
            return server.delivery.toCallToolResult(diffed, contract);
          const leftId = resolved.value.left.evidence_id;
          const rightId = resolved.value.right.evidence_id;
          const evidence = createEvidence(undefined, BINARY_DIFF_PROVIDER, {
            predicateType: "rea.binary-diff",
            operation: contract.name,
            parameters: {
              left_evidence_id: leftId,
              right_evidence_id: rightId,
            },
            result: diffed.value,
            confidence: "derived",
            authority: "analyst-inference",
            limitations: diffed.value.limitations,
            evidenceLinks: [leftId, rightId],
          });
          const recorded = recordDerivedEvidence(session, evidence, undefined);
          if (!recorded.ok)
            return server.delivery.toCallToolResult(recorded, contract);
          return server.delivery.toEvidenceToolResult(
            evidence,
            contract,
            recorded,
          );
        },
      ),
  );
};
