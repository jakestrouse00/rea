import { z } from "zod";

import {
  exportProtocolGrammarInputSchema,
  learnProtocolModelInputSchema,
  probeLearnedModelInputSchema,
} from "../../domain/protolearn/protocolLearningInputs.js";
import { protocolModelSchema } from "../../domain/protolearn/protocolModel.js";
import { protocolProbeResultSchema } from "../../domain/protolearn/protocolProbe.js";
import { protocolGrammarExportSchema } from "../../domain/protolearn/grammarExport.js";
import {
  PROTOLEARN_BRIDGE_DIR_ENV,
  PROTOLEARN_LAB_ENDPOINTS_ENV,
  PROTOLEARN_LIMITS,
  PROTOLEARN_PROBE_TIMEOUT_SETTING,
  PROTOLEARN_PYTHON_ENV,
} from "../../domain/protolearn/protolearnLimits.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** The learned model is the operation's whole result. */
export const learnProtocolModelResultSchema = z.strictObject({
  model: protocolModelSchema,
});

/**
 * The protocol learning loop answers three analyst questions: what state
 * machine does this capture show, does a lab service still answer the way the
 * model expects, and can the observed structure seed a fuzz campaign?
 */
export const PROTOLEARN_TOOL_CONTRACTS = [
  {
    name: "learn_protocol_model",
    ...toolContractMetadata("learn_protocol_model"),
    description: `Learn a finite-state model from one saved capture and report it as structure: message classes with field-type sketches and byte counts, states that are bounded suffixes of the observed message-class sequence, and counted transitions between them. Two evidence sources are read: a pcap or pcapng file through the packet-capture lane's own snapshot and ${"tshark"} selection (Linux needs util-linux prlimit, Windows owned Job Objects), or an aioquic JSON qlog 0.3 file through the owned capture decoder, which yields QUIC packet-type and frame-type structure. Payload values never appear: a class carries a digest, a length class, and delimiter-separated type tokens; an optional caller-owned model_directory receives the model file and one 0600 exemplar per class, which the probe and export operations read back. Message order only is modelled, so a state the capture never showed is absent rather than impossible. At most ${String(PROTOLEARN_LIMITS.maxMessages)} messages, ${String(PROTOLEARN_LIMITS.maxSessions)} conversations, and ${String(PROTOLEARN_LIMITS.maxClasses)} classes are retained; omissions and a reduced suffix length are reported as partial coverage.`,
    kind: "protocol-learning",
    inputSchema: learnProtocolModelInputSchema,
    outputSchema: evidenceResultOf(learnProtocolModelResultSchema),
    examples: [
      {
        title: "Learn a model from a saved capture and keep class templates",
        input: {
          source: { kind: "pcap", path: "/captures/lab-session.pcap" },
          max_states: 16,
          suffix_length: 2,
          model_directory: "/evidence/protolearn/lab-session",
        },
      },
      {
        title: "Learn QUIC packet structure from a qlog capture",
        input: {
          source: { kind: "qlog", path: "/captures/lab-session.qlog" },
          max_states: 8,
        },
      },
    ],
  },
  {
    name: "probe_learned_model",
    ...toolContractMetadata("probe_learned_model"),
    description: `Send caller-authored probe steps to one lab socket and compare each reply with what the learned model expects next. The endpoint must be an IPv4 or IPv6 literal the operator allowlisted in ${PROTOLEARN_LAB_ENDPOINTS_ENV}; an unset or mismatched allowlist refuses the request instead of probing. Each connection is a separate confined child process (${PROTOLEARN_PYTHON_ENV} interpreter, ${PROTOLEARN_BRIDGE_DIR_ENV} runner script) wrapped in the deny-default sandbox profile with exactly one outbound destination, so the network side effect is bounded by the kernel rather than by convention. Repeats detect a service whose replies vary; each step reports a verdict: consistent when the expected response class appeared, divergent when a different one did, unmodeled when the model has no expectation, and unstable when repeats disagreed. Replies are reported as lengths, SHA-256 digests, and type sketches only, so no response payload is echoed. The deadline of one connection is timeout_ms, otherwise ${PROTOLEARN_PROBE_TIMEOUT_SETTING} or ${PROTOLEARN_LIMITS.defaultProbeTimeoutMs} ms.`,
    kind: "protocol-learning",
    inputSchema: probeLearnedModelInputSchema,
    outputSchema: evidenceResultOf(protocolProbeResultSchema),
    examples: [
      {
        title: "Check one learned transition against a lab service twice",
        input: {
          endpoint: { host: "127.0.0.1", port: 9000 },
          model_path: "/evidence/protolearn/lab-session/model.json",
          probes: [
            {
              label: "baseline",
              steps: [{ template_hex: "68656c6c6f0a" }],
            },
          ],
          repeats: 2,
        },
      },
    ],
  },
  {
    name: "export_protocol_grammar",
    ...toolContractMetadata("export_protocol_grammar"),
    description: `Write structure-aware fuzz seeds from one learned model: each seed is the exemplar message sequence for the shortest observed path that reaches one transition, so a campaign begins from sequences the protocol actually showed instead of random bytes. The model must carry a template store from learn_protocol_model, and every class digest is verified before a byte is written; seed files are created 0600 in the caller's output_directory. The result names the handoff contract (rea.fuzzing.campaign-seeds/v1) and the exact seed paths for a fuzz campaign; this release begins none. A class with no exemplar (every qlog-derived model) or a seed above ${String(PROTOLEARN_LIMITS.maxSeedBytes)} bytes is counted as skipped rather than silently shortened, and covered_transitions reports the model transitions the written seeds reach, not the protocol's real states.`,
    kind: "protocol-learning",
    inputSchema: exportProtocolGrammarInputSchema,
    outputSchema: evidenceResultOf(protocolGrammarExportSchema),
    examples: [
      {
        title: "Export seeds covering every learned transition",
        input: {
          model_path: "/evidence/protolearn/lab-session/model.json",
          output_directory: "/evidence/protolearn/seeds",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
