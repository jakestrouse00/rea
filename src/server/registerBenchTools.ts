import type { Logger } from "pino";

import type { BenchTaskPort } from "../application/bench/BenchTaskPort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import { BENCH_LIMITS } from "../domain/bench/benchLimits.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export interface BenchToolRegistration {
  readonly server: EvidenceMcpServer;
  readonly bench: BenchTaskPort;
  readonly logger: Logger;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
}

/**
 * Register the benchmark harness on the long-lived MCP adapter.
 *
 * A failed task still returns the Evidence it observed, and a run whose lab VM
 * could not be released reports that in the same result rather than dropping
 * the identity.
 */
export const registerBenchTools = ({
  server,
  bench,
  logger,
  recordEvidence,
}: BenchToolRegistration): void => {
  const run = toolContract("run_bench_task");
  server.registerTool(
    run.name,
    toolRegistrationOptions(run),
    async (input, context) => {
      const executed = await logToolExecution(logger, run.name, () =>
        bench.run(
          {
            taskId: input.task_id,
            suite: input.suite,
            workspacePath: input.workspace_path,
            entrypoint: input.entrypoint,
            success: input.success,
            budgetSeconds:
              input.budget_seconds ?? BENCH_LIMITS.defaultTaskSeconds,
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!executed.ok)
        return server.delivery.toPartialErrorToolResult(
          executed.error,
          run.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        executed.value,
        run,
        recordEvidence?.(executed.value),
      );
    },
  );
};
