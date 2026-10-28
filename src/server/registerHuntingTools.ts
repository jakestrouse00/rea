import type { Logger } from "pino";

import type { HuntingQueuePort } from "../application/hunting/HuntingQueuePort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export interface HuntingToolRegistration {
  readonly server: EvidenceMcpServer;
  readonly hunting: HuntingQueuePort;
  readonly logger: Logger;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
}

/**
 * Register the durable hunting queue and its watch sessions.
 *
 * Every unit is a separate call, so a long batch is never run unattended
 * inside one tool reply. The queue records each outcome before replying, and a
 * failed unit keeps its queued work instead of dropping it.
 */
export const registerHuntingTools = ({
  server,
  hunting,
  logger,
  recordEvidence,
}: HuntingToolRegistration): void => {
  const schedule = toolContract("schedule_investigation_batch");
  server.registerTool(
    schedule.name,
    toolRegistrationOptions(schedule),
    async (input, context) => {
      const scheduled = await logToolExecution(logger, schedule.name, () =>
        hunting.schedule(
          {
            targets: input.targets,
            recipes: input.recipes,
            maxUnits: input.budget?.max_units,
            maxSeconds: input.budget?.max_seconds,
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!scheduled.ok)
        return server.delivery.toPartialErrorToolResult(
          scheduled.error,
          schedule.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        scheduled.value,
        schedule,
        recordEvidence?.(scheduled.value),
      );
    },
  );
  const run = toolContract("run_scheduled_batch");
  server.registerTool(
    run.name,
    toolRegistrationOptions(run),
    async (input, context) => {
      const executed = await logToolExecution(logger, run.name, () =>
        hunting.runNext(
          {
            batchId: input.batch_id,
            maxUnitSeconds: input.max_unit_seconds,
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
  const read = toolContract("read_hunting_queue");
  server.registerTool(
    read.name,
    toolRegistrationOptions(read),
    async (input, context) =>
      server.delivery.toCallToolResult(
        await logToolExecution(logger, read.name, () =>
          hunting.read(
            {
              batchId: input.batch_id,
              offset: input.offset,
              limit: input.limit,
            },
            { signal: context.mcpReq.signal },
          ),
        ),
        read,
      ),
  );
  const cancel = toolContract("cancel_hunting_batch");
  server.registerTool(
    cancel.name,
    toolRegistrationOptions(cancel),
    async (input, context) => {
      const released = await logToolExecution(logger, cancel.name, () =>
        hunting.cancel(
          { batchId: input.batch_id },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!released.ok)
        return server.delivery.toPartialErrorToolResult(
          released.error,
          cancel.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        released.value,
        cancel,
        recordEvidence?.(released.value),
      );
    },
  );
  const watchStart = toolContract("start_watch_session");
  server.registerTool(
    watchStart.name,
    toolRegistrationOptions(watchStart),
    async (input, context) => {
      const started = await logToolExecution(logger, watchStart.name, () =>
        hunting.startWatch(
          {
            source: input.source,
            target: input.target,
            operation: input.operation,
            intervalMs: input.interval_ms,
            maxTriggers: input.max_triggers,
            maxUnits: input.budget?.max_units,
            maxSeconds: input.budget?.max_seconds,
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!started.ok)
        return server.delivery.toPartialErrorToolResult(
          started.error,
          watchStart.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        started.value,
        watchStart,
        recordEvidence?.(started.value),
      );
    },
  );
  const watchStop = toolContract("stop_watch_session");
  server.registerTool(
    watchStop.name,
    toolRegistrationOptions(watchStop),
    async (input, context) => {
      const stopped = await logToolExecution(logger, watchStop.name, () =>
        hunting.stopWatch(
          { sessionId: input.session_id },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!stopped.ok)
        return server.delivery.toPartialErrorToolResult(
          stopped.error,
          watchStop.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        stopped.value,
        watchStop,
        recordEvidence?.(stopped.value),
      );
    },
  );
};
