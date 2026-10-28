import { z } from "zod";

import { digestSchema } from "../digests.js";
import {
  absoluteLocalPathStringSchema,
  localPathStringSchema,
} from "../localPath.js";
import { PROTOLEARN_LIMITS } from "./protolearnLimits.js";

const sourceFields = {
  path: localPathStringSchema.describe(
    "Local capture the model is learned from",
  ),
};

/** Caller intent for one model-learning run over one evidence source. */
export const learnProtocolModelInputSchema = z.strictObject({
  source: z.discriminatedUnion("kind", [
    z.strictObject({
      kind: z.literal("pcap"),
      ...sourceFields,
      path: sourceFields.path.describe(
        "Local pcap or pcapng capture read through the packet-capture lane",
      ),
    }),
    z.strictObject({
      kind: z.literal("qlog"),
      ...sourceFields,
      path: sourceFields.path.describe(
        "Local aioquic JSON qlog 0.3 capture read through the owned capture decoder",
      ),
    }),
  ]),
  max_states: z
    .int()
    .min(1)
    .max(PROTOLEARN_LIMITS.maxStates)
    .default(PROTOLEARN_LIMITS.defaultMaxStates)
    .describe("Upper bound on states the learned model retains"),
  suffix_length: z
    .int()
    .min(0)
    .max(PROTOLEARN_LIMITS.maxSuffixLength)
    .default(PROTOLEARN_LIMITS.defaultSuffixLength)
    .describe(
      "Message classes remembered as a state's suffix context; reduced to fit max_states",
    ),
  sensitive_values: z
    .array(z.string().min(1))
    .max(32)
    .default([])
    .describe(
      "Explicit caller-declared literals the qlog decoder must exclude; REA never guesses sensitivity from names",
    ),
  model_directory: absoluteLocalPathStringSchema
    .optional()
    .describe(
      "Absolute caller-owned directory that receives the model file and one exemplar payload per message class (0600); probe_learned_model and export_protocol_grammar read it back",
    ),
});

const probeStepSchema = z.strictObject({
  template_hex: z
    .string()
    .regex(/^(?:[0-9a-f]{2}){1,4096}$/u)
    .describe("Lowercase hex of the bytes this step sends"),
  wait_for_response: z
    .boolean()
    .default(true)
    .describe("Whether the step reads a response before the next step"),
});

const probeLabelSchema = z.strictObject({
  label: z
    .string()
    .regex(/^[a-z0-9][a-z0-9_\x2d]{0,31}$/u)
    .describe("Stable name for one probe connection"),
  steps: z
    .array(probeStepSchema)
    .min(1)
    .max(PROTOLEARN_LIMITS.maxProbeSteps),
});

/** Caller intent for differential probes against one allowlisted lab socket. */
export const probeLearnedModelInputSchema = z.strictObject({
  endpoint: z.strictObject({
    host: z
      .string()
      .min(1)
      .describe(
        "IPv4 or IPv6 literal of the lab service; a hostname cannot be expressed in the sandbox profile",
      ),
    port: z.int().min(1).max(65_535),
  }),
  model_path: absoluteLocalPathStringSchema.describe(
    "Absolute path of the model file learn_protocol_model wrote into its model_directory",
  ),
  probes: z
    .array(probeLabelSchema)
    .min(1)
    .max(PROTOLEARN_LIMITS.maxProbeLabels),
  repeats: z
    .int()
    .min(1)
    .max(PROTOLEARN_LIMITS.maxProbeRepeats)
    .default(PROTOLEARN_LIMITS.defaultProbeRepeats)
    .describe("Connections per probe label; repeats detect unstable responses"),
  timeout_ms: z
    .int()
    .min(1)
    .max(PROTOLEARN_LIMITS.maxProbeTimeoutMs)
    .optional()
    .describe(
      "Deadline of one probe connection; omitted means protolearn.probe_timeout_ms",
    ),
});

/** Caller intent for structure-aware seed export from one learned model. */
export const exportProtocolGrammarInputSchema = z.strictObject({
  model_path: absoluteLocalPathStringSchema.describe(
    "Absolute path of the model file whose transition structure the seeds cover",
  ),
  output_directory: absoluteLocalPathStringSchema.describe(
    "Absolute caller-owned directory that receives the seed files (0600)",
  ),
});

/** Supported protocol-learning operations. */
export type ProtolearnOperation =
  | "learn_protocol_model"
  | "probe_learned_model"
  | "export_protocol_grammar";

/** Validate operation and input together so their types remain correlated. */
export const protolearnRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("learn_protocol_model"),
    input: learnProtocolModelInputSchema,
  }),
  z.strictObject({
    operation: z.literal("probe_learned_model"),
    input: probeLearnedModelInputSchema,
  }),
  z.strictObject({
    operation: z.literal("export_protocol_grammar"),
    input: exportProtocolGrammarInputSchema,
  }),
]);

export type ProtolearnRequest = z.output<typeof protolearnRequestSchema>;

/** Identity of one exported seed, with the transitions it exercises. */
export const protocolGrammarSeedSchema = z.strictObject({
  seed_id: z.string().regex(/^seed-[0-9]{1,3}$/u),
  file: z.string().regex(/^[a-z0-9._\x2d]{1,64}$/u),
  bytes: z.int().positive().max(PROTOLEARN_LIMITS.maxSeedBytes),
  sha256: digestSchema,
  message_count: z.int().positive(),
  covers_transitions: z
    .array(
      z.strictObject({
        from: z.string().regex(/^s[0-9]{1,4}$/u),
        to: z.string().regex(/^s[0-9]{1,4}$/u),
        class_id: z.string().regex(/^c[0-9]{1,3}$/u),
      }),
    )
    .min(1),
});

export type ProtocolGrammarSeed = z.output<typeof protocolGrammarSeedSchema>;
