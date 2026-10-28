import type { Logger } from "pino";

import type { FuzzingCampaignPort } from "../application/fuzzing/FuzzingCampaignPort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { FUZZING_DEFAULT_POV_REPEATS } from "../domain/fuzzing/fuzzingEngine.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export interface FuzzingToolRegistration {
  readonly server: EvidenceMcpServer;
  readonly fuzzing: FuzzingCampaignPort;
  readonly logger: Logger;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
}

/**
 * Register the fuzz loop on the long-lived MCP adapter.
 *
 * The tool delivers the Evidence its owner recorded: the engine it launched,
 * the budget it enforced, the counters it observed, and the crashes it handed
 * to crash triage. Registration of a campaign stays the caller's first step.
 */
export const registerFuzzingTools = ({
  server,
  fuzzing,
  logger,
  recordEvidence,
}: FuzzingToolRegistration): void => {
  const contract = toolContract("start_fuzzing_campaign");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) => {
      if (
        input.lab_vm_session_id !== undefined &&
        input.lab_vm_workspace_path === undefined
      )
        return server.delivery.toPartialErrorToolResult(
          new AnalysisInputError(contract.name, {
            userMessage:
              "lab_vm_workspace_path is required with lab_vm_session_id; pass the host directory start_lab_vm reported.",
          }),
          contract.returnsTargetContent,
          recordEvidence,
        );
      const labVm =
        input.lab_vm_session_id === undefined
          ? null
          : {
              sessionId: input.lab_vm_session_id,
              workspacePath: input.lab_vm_workspace_path ?? "",
            };
      const recorded = await logToolExecution(logger, contract.name, () =>
        fuzzing.startCampaign(
          {
            campaignId: input.campaign_id,
            engine: input.engine,
            povRepeats: input.pov_repeats ?? FUZZING_DEFAULT_POV_REPEATS,
            expectedSanitizer: input.expected_sanitizer,
            minimizeCrashes: input.minimize_crashes ?? false,
            labVm,
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!recorded.ok)
        return server.delivery.toPartialErrorToolResult(
          recorded.error,
          contract.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        recorded.value,
        contract,
        recordEvidence?.(recorded.value),
      );
    },
  );
};
