import { z } from "zod";

import { digestSchema } from "../digests.js";
import {
  protocolClassIdSchema,
  protocolStateIdSchema,
  type ProtocolMessageClass,
  type ProtocolModel,
  type ProtocolTransition,
} from "./protocolModel.js";
import {
  messageClassKey,
  protocolMessageSketchSchema,
  type ProtocolMessageSketch,
} from "./protocolMessage.js";

export const PROBE_VERDICTS = [
  "consistent",
  "divergent",
  "unmodeled",
  "unstable",
] as const;
export type ProbeVerdict = (typeof PROBE_VERDICTS)[number];

/** Class lookups and transition adjacency derived once per probe request. */
export interface ProtocolModelIndex {
  readonly classByKey: ReadonlyMap<string, ProtocolMessageClass>;
  readonly classById: ReadonlyMap<string, ProtocolMessageClass>;
  readonly transitionsFrom: ReadonlyMap<string, readonly ProtocolTransition[]>;
  readonly initialState: string;
  readonly stateIds: ReadonlySet<string>;
}

/** Index one learned model for stepping it with observed messages. */
export const protocolModelIndex = (model: ProtocolModel): ProtocolModelIndex => {
  const classByKey = new Map<string, ProtocolMessageClass>();
  const classById = new Map<string, ProtocolMessageClass>();
  for (const messageClass of model.classes) {
    classById.set(messageClass.class_id, messageClass);
    classByKey.set(
      messageClassKey(messageClass.direction, messageClass.sketch),
      messageClass,
    );
  }
  const transitionsFrom = new Map<string, ProtocolTransition[]>();
  for (const transition of model.transitions) {
    const list = transitionsFrom.get(transition.from) ?? [];
    list.push(transition);
    transitionsFrom.set(transition.from, list);
  }
  for (const list of transitionsFrom.values())
    list.sort((left, right) =>
      left.class_id.localeCompare(right.class_id, "en"),
    );
  const emptyContext = model.states.find(
    ({ context }) => context.length === 0,
  );
  return {
    classByKey,
    classById,
    transitionsFrom,
    initialState: emptyContext?.state_id ?? model.states[0]?.state_id ?? "s0",
    stateIds: new Set(model.states.map(({ state_id }) => state_id)),
  };
};

/** One repeat's observation of a probe step's response. */
export interface ProbeStepObservation {
  readonly repeat: number;
  readonly response_bytes: number;
  readonly response_sha256: string | null;
  readonly response_class: string | null;
  readonly response_sketch: ProtocolMessageSketch | null;
  readonly timed_out: boolean;
}

export interface ProbeStepDiagnosis {
  readonly sent_class: string | null;
  readonly model: {
    readonly from: string;
    readonly to: string;
    readonly expected_response_classes: readonly string[];
  } | null;
  readonly verdict: ProbeVerdict;
  /** Model state the machine steps to after this message. */
  readonly next_state: string;
}

/**
 * Compare one probe step's repeated observations with the model's expectation.
 *
 * Repeats that disagree on exact response bytes make the step unstable before
 * any expectation is judged, because a lab service whose own replies vary
 * cannot support a differential verdict.
 */
export const diagnoseProbeStep = (
  index: ProtocolModelIndex,
  state: string,
  sentSketch: ProtocolMessageSketch,
  observations: readonly ProbeStepObservation[],
): ProbeStepDiagnosis => {
  const sentClass =
    index.classByKey.get(messageClassKey("request", sentSketch))?.class_id ??
    null;
  const transition =
    sentClass === null
      ? undefined
      : index.transitionsFrom
          .get(state)
          ?.find(({ class_id }) => class_id === sentClass);
  if (transition === undefined)
    return {
      sent_class: sentClass,
      model: null,
      verdict: "unmodeled",
      next_state: state,
    };
  const expected = (index.transitionsFrom.get(transition.to) ?? [])
    .filter(({ class_id }) => {
      const messageClass = index.classById.get(class_id);
      return messageClass?.direction === "response";
    })
    .map(({ class_id }) => class_id)
    .sort((left, right) => left.localeCompare(right, "en"));
  const digests = new Set(
    observations.map(
      ({ response_sha256, timed_out }) =>
        timed_out ? "timeout" : (response_sha256 ?? "absent"),
    ),
  );
  const stable = digests.size <= 1;
  const matched =
    expected.length > 0 &&
    observations.every(
      ({ response_class, timed_out }) =>
        !timed_out &&
        response_class !== null &&
        expected.includes(response_class),
    );
  return {
    sent_class: sentClass,
    model: {
      from: transition.from,
      to: transition.to,
      expected_response_classes: expected,
    },
    verdict: !stable
      ? "unstable"
      : expected.length === 0
        ? "unmodeled"
        : matched
          ? "consistent"
          : "divergent",
    next_state: transition.to,
  };
};

/** One probe connection's verdict table. */
export const protocolProbeLabelResultSchema = z.strictObject({
  label: z.string().regex(/^[a-z0-9][a-z0-9_\x2d]{0,31}$/u),
  repeats: z.int().positive(),
  stable: z.boolean(),
  steps: z.array(
    z.strictObject({
      ordinal: z.int().nonnegative(),
      sent_bytes: z.int().nonnegative(),
      sent_sha256: digestSchema,
      sent_class: protocolClassIdSchema.nullable(),
      model: z
        .strictObject({
          from: protocolStateIdSchema,
          to: protocolStateIdSchema,
          expected_response_classes: z.array(protocolClassIdSchema),
        })
        .nullable(),
      observations: z.array(
        z.strictObject({
          repeat: z.int().nonnegative(),
          timed_out: z.boolean(),
          response_bytes: z.int().nonnegative(),
          response_sha256: digestSchema.nullable(),
          response_class: protocolClassIdSchema.nullable(),
          response_sketch: protocolMessageSketchSchema.nullable(),
        }),
      ),
      verdict: z.enum(PROBE_VERDICTS),
    }),
  ),
});

/** Differential probe observations, as structure and hashes only. */
export const protocolProbeResultSchema = z.strictObject({
  endpoint: z.strictObject({
    host: z.string().min(1),
    port: z.int().positive(),
    /** True only when the operator allowlist approved this exact literal. */
    operator_allowlisted: z.literal(true),
  }),
  sandbox: z.strictObject({
    confinement: z.enum(["enforced", "disabled"]),
    profile: z.literal("deny-default"),
    limitation: z.string().min(1).nullable(),
  }),
  probes: z.array(protocolProbeLabelResultSchema),
  counts: z.strictObject({
    consistent: z.int().nonnegative(),
    divergent: z.int().nonnegative(),
    unmodeled: z.int().nonnegative(),
    unstable: z.int().nonnegative(),
    steps: z.int().nonnegative(),
  }),
  limitations: z.array(z.string().min(1)),
});

export type ProtocolProbeResult = z.output<typeof protocolProbeResultSchema>;
