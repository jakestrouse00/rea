import type { Logger } from "pino";

import type { CrashTriagePort } from "../application/crashTriage/CrashTriagePort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import { CRASH_STATE_DEFAULT_FRAMES } from "../domain/crashTriage/crashStateHash.js";
import { CRASH_TRIAGE_MAX_DEDUP_GROUPS_DEFAULT } from "../domain/crashTriage/fuzzingCampaign.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export interface CrashTriageToolRegistration {
  readonly server: EvidenceMcpServer;
  readonly crashTriage: CrashTriagePort;
  readonly logger: Logger;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
}

/**
 * Register campaign bookkeeping on the long-lived MCP adapter.
 *
 * Each tool delivers the Evidence its owner recorded. Registration digests the
 * caller's files; the reads report stored counters, deduplicated groups, and
 * one crash's structural facts. No engine is started here.
 */
export const registerCrashTriageTools = ({
  server,
  crashTriage,
  logger,
  recordEvidence,
}: CrashTriageToolRegistration): void => {
  const register = toolContract("register_fuzzing_campaign");
  server.registerTool(
    register.name,
    toolRegistrationOptions(register),
    async (input, context) => {
      const recorded = await logToolExecution(logger, register.name, () =>
        crashTriage.registerCampaign(
          {
            targetPath: input.target_path,
            seedPaths: input.seed_paths ?? [],
            budget: input.budget,
            dedupFrames: input.dedup_frames ?? CRASH_STATE_DEFAULT_FRAMES,
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!recorded.ok)
        return server.delivery.toPartialErrorToolResult(
          recorded.error,
          register.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        recorded.value,
        register,
        recordEvidence?.(recorded.value),
      );
    },
  );
  const status = toolContract("read_campaign_status");
  server.registerTool(
    status.name,
    toolRegistrationOptions(status),
    async (input, context) => {
      const recorded = await logToolExecution(logger, status.name, () =>
        crashTriage.campaignStatus(
          { campaignId: input.campaign_id },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!recorded.ok)
        return server.delivery.toPartialErrorToolResult(
          recorded.error,
          status.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        recorded.value,
        status,
        recordEvidence?.(recorded.value),
      );
    },
  );
  const list = toolContract("list_crash_dedups");
  server.registerTool(
    list.name,
    toolRegistrationOptions(list),
    async (input, context) => {
      const recorded = await logToolExecution(logger, list.name, () =>
        crashTriage.listDedups(
          {
            campaignId: input.campaign_id,
            limit: input.limit ?? CRASH_TRIAGE_MAX_DEDUP_GROUPS_DEFAULT,
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!recorded.ok)
        return server.delivery.toPartialErrorToolResult(
          recorded.error,
          list.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        recorded.value,
        list,
        recordEvidence?.(recorded.value),
      );
    },
  );
  const fetch = toolContract("fetch_crash_evidence");
  server.registerTool(
    fetch.name,
    toolRegistrationOptions(fetch),
    async (input, context) => {
      const recorded = await logToolExecution(logger, fetch.name, () =>
        crashTriage.fetchCrashEvidence(
          { campaignId: input.campaign_id, crashId: input.crash_id },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!recorded.ok)
        return server.delivery.toPartialErrorToolResult(
          recorded.error,
          fetch.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        recorded.value,
        fetch,
        recordEvidence?.(recorded.value),
      );
    },
  );
};
