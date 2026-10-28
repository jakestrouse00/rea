import type { Logger } from "pino";

import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export interface LabVmToolRegistration {
  readonly server: EvidenceMcpServer;
  readonly labVm: LabVmPort;
  readonly logger: Logger;
  readonly recordEvidence: EvidenceWriter["recordEvidence"];
}

/**
 * Register the caller-supplied Lima lab-VM lifecycle on the long-lived MCP
 * adapter. Each tool delivers the Evidence its owner observed and keeps any
 * partial observation on a timeout, cancellation, or failed cleanup.
 */
export const registerLabVmTools = ({
  server,
  labVm,
  logger,
  recordEvidence,
}: LabVmToolRegistration): void => {
  const start = toolContract("start_lab_vm");
  const run = toolContract("run_lab_vm_command");
  const stop = toolContract("stop_lab_vm");
  server.registerTool(
    start.name,
    toolRegistrationOptions(start),
    async (input, context) => {
      const started = await logToolExecution(logger, start.name, () =>
        labVm.start(
          { workspacePath: input.workspace_path },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!started.ok)
        return server.delivery.toPartialErrorToolResult(
          started.error,
          start.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        started.value,
        start,
        recordEvidence(started.value),
      );
    },
  );
  server.registerTool(
    run.name,
    toolRegistrationOptions(run),
    async (input, context) => {
      const executed = await logToolExecution(logger, run.name, () =>
        labVm.run(
          {
            sessionId: input.session_id,
            command: input.command,
            timeoutMs:
              input.command_timeout_ms ?? labVm.defaultCommandTimeoutMs,
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
        recordEvidence(executed.value),
      );
    },
  );
  server.registerTool(
    stop.name,
    toolRegistrationOptions(stop),
    async (input, context) => {
      const stopped = await logToolExecution(logger, stop.name, () =>
        labVm.stop(
          { sessionId: input.session_id },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!stopped.ok)
        return server.delivery.toPartialErrorToolResult(
          stopped.error,
          stop.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        stopped.value,
        stop,
        recordEvidence(stopped.value),
      );
    },
  );
};
