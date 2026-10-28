import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createAnalysisExecution } from "../../../src/application/AnalysisProvider.js";
import type { FuzzingCampaignPort } from "../../../src/application/fuzzing/FuzzingCampaignPort.js";
import type { MitmInterceptionPort } from "../../../src/application/mitm/MitmInterceptionPort.js";
import type { ProtocolLearningPort } from "../../../src/application/protolearn/ProtocolLearningPort.js";
import { AnalysisCapabilityUnavailableError } from "../../../src/domain/analysisErrorCore.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import { FUZZING_PROVIDER } from "../../../src/domain/fuzzing/fuzzingEngine.js";
import { MITM_PROVIDER } from "../../../src/domain/mitm/mitmLimits.js";
import { PROTOLEARN_QLOG_PROFILE } from "../../../src/domain/protolearn/protolearnLimits.js";
import {
  protocolModelSchema,
  type ProtocolModel,
} from "../../../src/domain/protolearn/protocolModel.js";
import { err, ok } from "../../../src/domain/result.js";
import { PROTOLEARN_PROVIDER_IDENTITY } from "../../../src/protolearn/ProtocolLearningProvider.js";

const sessionId = "8a4c6f0b-5d2e-4a1c-9b7f-3e2d1c0b9a87";

/**
 * Build the learned model Loop B scores.
 *
 * This is the protocol-learning lane's own model schema: a synthetic
 * single-class alphabet stands in for a decoded capture, and no payload bytes
 * are retained.
 */
export const buildProtocolModel = (
  storeDirectory: string | null,
  source: { readonly path: string; readonly sha256: string },
): ProtocolModel =>
  protocolModelSchema.parse({
    source: {
      kind: "qlog",
      path: source.path,
      sha256: source.sha256,
      profile: PROTOLEARN_QLOG_PROFILE,
      traces: 1,
    },
    sessions: { total: 1, retained: 1, omitted: 0 },
    messages: {
      total: 2,
      retained: 2,
      omitted: 0,
      request: 0,
      response: 2,
      unattributed: 0,
    },
    alphabet: { class_count: 1, omitted: 0, sketch_kinds: ["text"] },
    classes: [
      {
        class_id: "c0",
        direction: "response",
        sketch: {
          kind: "text",
          printable_ratio: "high",
          line_terminated: true,
          segments: 1,
          segment_types: ["alpha"],
          examined_bytes: 16,
        },
        message_count: 2,
        byte_length: { min: 0, max: 0, total: 0 },
        segment_count: { min: 0, max: 0 },
        positions: [],
        exemplar_sha256: null,
        template: null,
      },
    ],
    states: [
      {
        state_id: "s0",
        context: [],
        message_count: 2,
        session_ends: 1,
        accepting: true,
      },
    ],
    transitions: [],
    merge: {
      requested_suffix_length: 0,
      retained_suffix_length: 0,
      max_states: 8,
      suffix_reduced: false,
    },
    coverage: "complete",
    model_store:
      storeDirectory === null
        ? null
        : {
            directory: storeDirectory,
            model_file: "model.json",
            template_count: 0,
          },
    limitations: [
      "Synthetic single-class model: this eval scores the export, not the learner.",
    ],
  });

export interface ScriptedFuzzingOptions {
  readonly acceptedPovs: number;
  readonly declaredSeconds: number;
  readonly consumedSeconds: number;
  readonly status?: "finished" | "stopped";
}

export interface ScriptedFuzzing extends FuzzingCampaignPort {
  readonly requests: unknown[];
}

/** Loop A: a fuzzing lane that reports a POV count and the budget it enforced. */
export const scriptedFuzzingCampaign = (
  options: ScriptedFuzzingOptions,
): ScriptedFuzzing => {
  const requests: unknown[] = [];
  return {
    requests,
    startCampaign: async (request) => {
      requests.push(request);
      return ok(
        createEvidence(undefined, FUZZING_PROVIDER, {
          predicateType: "fuzzing-campaign",
          operation: "start_fuzzing_campaign",
          parameters: {
            campaign_id: request.campaignId,
            engine: request.engine,
          },
          result: {
            status: options.status ?? "stopped",
            budget: {
              effective: {
                max_runs: null,
                max_seconds: options.declaredSeconds,
                max_crashes: null,
              },
              seconds_bound: "declared",
            },
            consumed: {
              runs: 1_000,
              seconds: options.consumedSeconds,
              observed_crashes: options.acceptedPovs,
            },
            crashes: { accepted: options.acceptedPovs },
          },
          confidence: "observed",
          authority: "controlled-replay",
          environment: null,
          limitations: ["Scripted lane: no engine was launched."],
          locations: [],
        }),
      );
    },
    closeAll: async () => ok(null),
  };
};

export interface ScriptedProtolearn extends ProtocolLearningPort {
  readonly requests: unknown[];
}

/** Loop B: a protocol-learning lane that writes the model to the caller's store. */
export const scriptedProtocolLearning = (
  model: ProtocolModel,
): ScriptedProtolearn => {
  const requests: unknown[] = [];
  return {
    requests,
    inspectProbeAvailability: async () => ({
      status: "unavailable",
      code: "not_configured",
      reason: "The scripted lane opens no socket",
      diagnostics: {},
    }),
    close: async () => undefined,
    execute: async (request) => {
      requests.push(request);
      if (request.operation !== "learn_protocol_model")
        return err(
          new AnalysisCapabilityUnavailableError(
            PROTOLEARN_PROVIDER_IDENTITY.id,
            request.operation,
            "The scripted lane learns a model only",
          ),
        );
      const store = model.model_store;
      if (store !== null) {
        await mkdir(store.directory, { recursive: true });
        await writeFile(
          join(store.directory, store.model_file),
          JSON.stringify(model),
        );
      }
      return ok(
        createAnalysisExecution({ model }, PROTOLEARN_PROVIDER_IDENTITY, {
          limitations: model.limitations,
          locations:
            store === null
              ? []
              : [{ kind: "artifact-path", path: store.directory }],
        }),
      );
    },
  };
};

export interface ScriptedMitmOptions {
  readonly captureDirectory: string;
  readonly origin: string;
  readonly pathTemplate: string;
  readonly bodiesHeld: number;
}

export interface ScriptedMitm extends MitmInterceptionPort {
  readonly starts: unknown[];
  readonly reads: unknown[];
}

const startResult = (options: ScriptedMitmOptions) => ({
  session_id: sessionId,
  state: "capturing" as const,
  daemon: {
    pid: 4_242,
    mitmproxy_version: "11.0.0",
    addon: { id: "rea-mitm-addon", version: 1 },
    running: true,
  },
  listen: {
    host: "127.0.0.1" as const,
    port: 8_081,
    proxy_url: "http://127.0.0.1:8081",
  },
  capture: {
    directory: options.captureDirectory,
    entries: options.bodiesHeld,
    entries_omitted: 0,
    permissions: "0700" as const,
  },
  proxy_guidance: {
    target_app: "other" as const,
    per_app_only: true as const,
    steps: ["Point the fixture client at the proxy."],
    out_of_scope: ["No system trust store change."],
  },
  tls: {
    scope: "per-application" as const,
    trust_store_changes: "out-of-scope" as const,
    device_wide_interception: "out-of-scope" as const,
    ca: {
      supplied_by: "caller" as const,
      served_at: "http://mitm.it" as const,
    },
  },
  target_origins: [options.origin],
  retry: "none" as const,
  limitations: ["Scripted lane: no proxy was started."],
});

const inventoryResult = (options: ScriptedMitmOptions) => ({
  session_id: sessionId,
  state: "capturing",
  daemon: startResult(options).daemon,
  listen: startResult(options).listen,
  capture: startResult(options).capture,
  target_origins: [options.origin],
  totals: {
    flows: options.bodiesHeld,
    endpoints: 1,
    endpoints_omitted: 0,
    facts_omitted: 0,
    requests_without_response: 0,
    bodies_held: options.bodiesHeld,
    body_bytes_held: 32,
  },
  endpoints: [
    {
      origin: options.origin,
      method: "POST",
      path_template: options.pathTemplate,
      occurrences: options.bodiesHeld,
      first_at: "2026-10-28T00:00:00.000Z",
      last_at: "2026-10-28T00:00:01.000Z",
      status_histogram: [{ status: 200, status_class: "success", count: 1 }],
      request_header_names: ["content-type"],
      response_header_names: ["content-type"],
      parameters: [{ name: "state", location: "query", types: ["hex"] }],
      response_shape: { kind: "scalar", type: "text" },
      shape_variants: 0,
    },
  ],
  next_offset: null,
  stream: {
    lines: 4,
    events: 1,
    malformed: 0,
    oversized: 0,
    unknown_type: 0,
    unknown_rule_matches: 0,
    notices: 0,
    errors: 0,
    last_error: null,
  },
  rules: [],
  retry: "none",
  limitations: ["Scripted lane: no proxy was started."],
});

/** Loop C: an interception lane that reports the capture directory it owns. */
export const scriptedMitm = (options: ScriptedMitmOptions): ScriptedMitm => {
  const starts: unknown[] = [];
  const reads: unknown[] = [];
  return {
    starts,
    reads,
    start: async (request) => {
      starts.push(request);
      return ok(
        createEvidence(undefined, MITM_PROVIDER, {
          predicateType: "mitm-interception-session",
          operation: "start_interception_session",
          parameters: { session_id: sessionId },
          result: startResult(options),
          confidence: "observed",
          authority: "controlled-replay",
          environment: null,
          limitations: ["Scripted lane: no proxy was started."],
          locations: [
            { kind: "artifact-path", path: options.captureDirectory },
          ],
          subjectUnavailableReason:
            "The proxy observes traffic a caller routed to it.",
        }),
      );
    },
    readInventory: async (request) => {
      reads.push(request);
      return ok(
        createEvidence(undefined, MITM_PROVIDER, {
          predicateType: "mitm-interception-session",
          operation: "read_interception_inventory",
          parameters: { session_id: request.sessionId },
          result: inventoryResult(options),
          confidence: "observed",
          authority: "controlled-replay",
          environment: null,
          limitations: ["Scripted lane: no proxy was started."],
          locations: [
            { kind: "artifact-path", path: options.captureDirectory },
          ],
          subjectUnavailableReason:
            "The inventory describes traffic a caller routed to this proxy.",
        }),
      );
    },
    exportInventory: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          MITM_PROVIDER.id,
          "export_endpoint_inventory",
          "The scripted lane exports nothing",
        ),
      ),
    setRule: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          MITM_PROVIDER.id,
          "proxy_rule_set",
          "The scripted lane arms no rule",
        ),
      ),
    clearRule: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          MITM_PROVIDER.id,
          "proxy_rule_clear",
          "The scripted lane arms no rule",
        ),
      ),
    replay: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          MITM_PROVIDER.id,
          "proxy_replay_send",
          "The scripted lane replays nothing",
        ),
      ),
    stop: async () =>
      ok(
        createEvidence(undefined, MITM_PROVIDER, {
          predicateType: "mitm-interception-session",
          operation: "stop_interception_session",
          parameters: { session_id: sessionId },
          result: {
            session_id: sessionId,
            state: "stopped",
            daemon: {
              pid: 4_242,
              exit: { kind: "exited", code: 0, signal: null },
            },
            capture: { directory: options.captureDirectory, removed: false },
            rules_released: 0,
            retry: "none",
            limitations: [],
          },
          confidence: "observed",
          authority: "controlled-replay",
          environment: null,
          limitations: ["Scripted lane: no proxy was started."],
          locations: [],
          subjectUnavailableReason:
            "The proxy observes traffic a caller routed to it.",
        }),
      ),
    closeAll: async () => ok(undefined),
  };
};
