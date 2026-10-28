import type { Logger } from "pino";

import type { MitmInterceptionPort } from "../application/mitm/MitmInterceptionPort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export interface MitmToolRegistration {
  readonly server: EvidenceMcpServer;
  readonly mitm: MitmInterceptionPort;
  readonly logger: Logger;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
}

/**
 * Register the interception lane on the long-lived MCP adapter. Every tool
 * delivers the Evidence its owner observed and keeps partial observations on a
 * cancellation or failed cleanup.
 */
export const registerMitmTools = ({
  server,
  mitm,
  logger,
  recordEvidence,
}: MitmToolRegistration): void => {
  const start = toolContract("start_interception_session");
  server.registerTool(
    start.name,
    toolRegistrationOptions(start),
    async (input, context) => {
      const started = await logToolExecution(logger, start.name, () =>
        mitm.start(
          {
            targetApp: input.target_app,
            appIdentifier: input.app_identifier,
            listenPort: input.listen_port,
            targetOrigins: input.target_origins,
            startTimeoutMs: input.start_timeout_ms,
          },
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
        recordEvidence?.(started.value),
      );
    },
  );
  const read = toolContract("read_interception_inventory");
  server.registerTool(
    read.name,
    toolRegistrationOptions(read),
    async (input, context) => {
      const inventory = await logToolExecution(logger, read.name, () =>
        mitm.readInventory(
          {
            sessionId: input.session_id,
            offset: input.offset,
            limit: input.limit,
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!inventory.ok)
        return server.delivery.toPartialErrorToolResult(
          inventory.error,
          read.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        inventory.value,
        read,
        recordEvidence?.(inventory.value),
      );
    },
  );
  const exportInventory = toolContract("export_endpoint_inventory");
  server.registerTool(
    exportInventory.name,
    toolRegistrationOptions(exportInventory),
    async (input, context) => {
      const exported = await logToolExecution(
        logger,
        exportInventory.name,
        () =>
          mitm.exportInventory(
            {
              sessionId: input.session_id,
              path: input.path,
              overwrite: input.overwrite,
            },
            { signal: context.mcpReq.signal },
          ),
      );
      if (!exported.ok)
        return server.delivery.toPartialErrorToolResult(
          exported.error,
          exportInventory.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        exported.value,
        exportInventory,
        recordEvidence?.(exported.value),
      );
    },
  );
  const setRule = toolContract("proxy_rule_set");
  server.registerTool(
    setRule.name,
    toolRegistrationOptions(setRule),
    async (input, context) => {
      const action = input.action;
      const armed = await logToolExecution(logger, setRule.name, () =>
        mitm.setRule(
          {
            sessionId: input.session_id,
            ruleId: input.rule_id,
            match: {
              origins: input.match.origins,
              pathPrefixes: input.match.path_prefixes,
              methods: input.match.methods,
            },
            action:
              action.kind === "request"
                ? {
                    kind: "request",
                    setHeaders: action.set_headers,
                    removeHeaders: action.remove_headers,
                    setQuery: action.set_query,
                    removeQuery: action.remove_query,
                    bodyBase64: action.body_base64,
                  }
                : {
                    kind: "response",
                    setHeaders: action.set_headers,
                    removeHeaders: action.remove_headers,
                    status: action.status,
                    bodyBase64: action.body_base64,
                  },
            ttlMs: input.ttl_ms,
          },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!armed.ok)
        return server.delivery.toPartialErrorToolResult(
          armed.error,
          setRule.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        armed.value,
        setRule,
        recordEvidence?.(armed.value),
      );
    },
  );
  const clearRule = toolContract("proxy_rule_clear");
  server.registerTool(
    clearRule.name,
    toolRegistrationOptions(clearRule),
    async (input, context) => {
      const cleared = await logToolExecution(logger, clearRule.name, () =>
        mitm.clearRule(
          { sessionId: input.session_id, ruleId: input.rule_id },
          { signal: context.mcpReq.signal },
        ),
      );
      if (!cleared.ok)
        return server.delivery.toPartialErrorToolResult(
          cleared.error,
          clearRule.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        cleared.value,
        clearRule,
        recordEvidence?.(cleared.value),
      );
    },
  );
  const replay = toolContract("proxy_replay_send");
  server.registerTool(
    replay.name,
    toolRegistrationOptions(replay),
    async (input, context) => {
      const sent = await logToolExecution(logger, replay.name, () =>
        mitm.replay(
          {
            sessionId: input.session_id,
            sequence: input.sequence,
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
      if (!sent.ok)
        return server.delivery.toPartialErrorToolResult(
          sent.error,
          replay.returnsTargetContent,
          recordEvidence,
        );
      return server.delivery.toEvidenceToolResult(
        sent.value,
        replay,
        recordEvidence?.(sent.value),
      );
    },
  );
  const stop = toolContract("stop_interception_session");
  server.registerTool(
    stop.name,
    toolRegistrationOptions(stop),
    async (input, context) => {
      const stopped = await logToolExecution(logger, stop.name, () =>
        mitm.stop(
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
        recordEvidence?.(stopped.value),
      );
    },
  );
};
