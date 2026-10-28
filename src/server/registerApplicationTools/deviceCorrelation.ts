import type { EvidenceMcpServer } from "../EvidenceMcpServer.js";
import { runAdmittedToolOperation } from "../admittedToolOperation.js";
import {
  correlateDeviceEvidence,
  type DeviceEvidenceReader,
} from "../../application/correlation/DeviceCorrelationWorkflow.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { err, type Result } from "../../domain/result.js";
import { toolContract } from "../../contracts/toolContracts.js";
import { logToolExecution } from "../toolLogging.js";
import { toolRegistrationOptions } from "../toolRegistrationOptions.js";
import type { ApplicationToolRegistration } from "./types.js";

const correlateContract = toolContract("correlate_device_evidence");

/**
 * Register the query-only device-identity correlation workflow. It reads the
 * session ledger synchronously; no Evidence is recorded.
 */
export const registerCorrelateDeviceEvidenceTool = (
  server: EvidenceMcpServer,
  options: ApplicationToolRegistration,
): void => {
  server.registerTool(
    correlateContract.name,
    toolRegistrationOptions(correlateContract),
    async (input, context) =>
      runAdmittedToolOperation(
        server,
        options.withAdmittedAnalysis,
        correlateContract.name,
        context.mcpReq.signal,
        async () => {
          const reader: DeviceEvidenceReader | undefined = options.evidenceById;
          const result =
            reader === undefined
              ? err(
                  new AnalysisInputError(correlateContract.name, {
                    userMessage:
                      "The session's evidence ledger is unavailable, so no retained record can be read for correlation",
                  }),
                )
              : await logToolExecution(
                  options.logger,
                  correlateContract.name,
                  () =>
                    Promise.resolve(
                      correlateDeviceEvidence(
                        input,
                        reader,
                      ) as unknown as Result<JsonValue, AnalysisError>,
                    ),
                );
          return server.delivery.toCallToolResult(result, correlateContract);
        },
      ),
  );
};
