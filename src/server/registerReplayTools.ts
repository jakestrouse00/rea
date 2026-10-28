import type { Logger } from "pino";
import type { z } from "zod";

import type { ReplayPort } from "../application/replay/ReplayPort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { httpReplaySessionStartInputSchema } from "../contracts/replay/replayInputSchemas.js";
import { toolContract } from "../contracts/toolContracts.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import type { ReplayRequest } from "../domain/replay/replayRequest.js";
import { err } from "../domain/result.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export interface ReplayToolRegistration {
  readonly server: EvidenceMcpServer;
  readonly replay: ReplayPort;
  readonly logger: Logger;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
}

/** Register the active request plane on the long-lived MCP adapter. */
export const registerReplayTools = ({
  server,
  replay,
  logger,
  recordEvidence,
}: ReplayToolRegistration): void => {
  const start = toolContract("http_replay_session_start");
  server.registerTool(
    start.name,
    toolRegistrationOptions(start),
    async (input, context) => {
      const source = replaySource(input);
      const recorded = await logToolExecution(logger, start.name, () =>
        source.ok
          ? replay.startSession(
              { source: source.value, targetOrigins: input.target_origins },
              { signal: context.mcpReq.signal },
            )
          : Promise.resolve(err(source.error)),
      );
      if (!recorded.ok)
        return server.delivery.toPartialErrorToolResult(
          recorded.error,
          start.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        recorded.value,
        start,
        recordEvidence?.(recorded.value),
      );
    },
  );
  const send = toolContract("http_replay_send");
  server.registerTool(
    send.name,
    toolRegistrationOptions(send),
    async (input, context) => {
      const recorded = await logToolExecution(logger, send.name, () =>
        replay.send(
          {
            sessionId: input.session_id,
            entryOrdinal: input.entry_ordinal,
            mutation: {
              ...(input.method === undefined ? {} : { method: input.method }),
              ...(input.url === undefined ? {} : { url: input.url }),
              ...(input.set_headers === undefined
                ? {}
                : { setHeaders: input.set_headers }),
              ...(input.remove_headers === undefined
                ? {}
                : { removeHeaders: input.remove_headers }),
              ...(input.body === undefined ? {} : { body: input.body }),
            },
            timeoutMs: input.timeout_ms,
            followRedirects: input.follow_redirects,
            dump:
              input.dump_path === undefined
                ? undefined
                : { path: input.dump_path, overwrite: input.overwrite },
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!recorded.ok)
        return server.delivery.toPartialErrorToolResult(
          recorded.error,
          send.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        recorded.value,
        send,
        recordEvidence?.(recorded.value),
      );
    },
  );
  const status = toolContract("http_replay_session_status");
  server.registerTool(
    status.name,
    toolRegistrationOptions(status),
    async (input, context) => {
      const recorded = await logToolExecution(logger, status.name, () =>
        replay.sessionStatus(
          { sessionId: input.session_id },
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
  const close = toolContract("http_replay_session_close");
  server.registerTool(
    close.name,
    toolRegistrationOptions(close),
    async (input, context) => {
      const recorded = await logToolExecution(logger, close.name, () =>
        replay.closeSession(
          { sessionId: input.session_id },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!recorded.ok)
        return server.delivery.toPartialErrorToolResult(
          recorded.error,
          close.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        recorded.value,
        close,
        recordEvidence?.(recorded.value),
      );
    },
  );
};

type StartInput = z.output<typeof httpReplaySessionStartInputSchema>;

const replaySource = (
  input: StartInput,
):
  | {
      readonly ok: true;
      readonly value:
        | {
            readonly kind: "har";
            readonly path: string;
            readonly entryOrdinal: number | undefined;
          }
        | { readonly kind: "draft"; readonly request: ReplayRequest };
    }
  | { readonly ok: false; readonly error: AnalysisInputError } => {
  // A cross-field refinement is not carried by the advertised JSON Schema, so
  // the handler enforces "exactly one source" before any session is created.
  if (input.capture_path !== undefined && input.request !== undefined)
    return {
      ok: false,
      error: new AnalysisInputError("http_replay_session_start", {
        userMessage:
          "Supply exactly one source: capture_path for a HAR entry, or request for a drafted request.",
      }),
    };
  if (input.capture_path !== undefined)
    return {
      ok: true,
      value: {
        kind: "har",
        path: input.capture_path,
        entryOrdinal: input.entry_ordinal,
      },
    };
  const request = input.request;
  if (request === undefined)
    return {
      ok: false,
      error: new AnalysisInputError("http_replay_session_start", {
        userMessage:
          "Supply exactly one source: capture_path for a HAR entry, or request for a drafted request.",
      }),
    };
  const draft: ReplayRequest = {
    method: request.method,
    url: request.url,
    headers: request.headers,
    body: request.body,
  };
  return { ok: true, value: { kind: "draft", request: draft } };
};
