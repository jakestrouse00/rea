import type {
  ProtocolDirection,
  ProtocolMessageFact,
  ProtocolMessageSketch,
} from "./protocolMessage.js";
import { messageClassKey, payloadDigest } from "./protocolMessage.js";
import type {
  ProtocolMessageClass,
  ProtocolState,
  ProtocolTransition,
} from "./protocolModel.js";
import { PROTOLEARN_LIMITS } from "./protolearnLimits.js";

/** One observed conversation: its stable identity and ordered messages. */
export interface ProtocolSessionFact {
  readonly session: string;
  readonly messages: readonly ProtocolMessageFact[];
}

export interface LearnProtocolModelOptions {
  readonly max_states: number;
  readonly suffix_length: number;
}

/** Everything a model learns besides its source identity and limitations. */
export interface LearnedProtocolModel {
  readonly sessions: {
    readonly total: number;
    readonly retained: number;
    readonly omitted: number;
  };
  readonly messages: {
    readonly total: number;
    readonly retained: number;
    readonly omitted: number;
    readonly request: number;
    readonly response: number;
    readonly unattributed: number;
  };
  readonly alphabet: {
    readonly class_count: number;
    readonly omitted: number;
    readonly sketch_kinds: readonly ProtocolMessageSketch["kind"][];
  };
  readonly classes: readonly ProtocolMessageClass[];
  readonly states: readonly ProtocolState[];
  readonly transitions: readonly ProtocolTransition[];
  readonly merge: {
    readonly requested_suffix_length: number;
    readonly retained_suffix_length: number;
    readonly max_states: number;
    readonly suffix_reduced: boolean;
  };
  readonly coverage: "complete" | "partial";
  /** Exemplar payload per class id, retained only for a caller-declared store. */
  readonly templates: ReadonlyMap<string, Buffer>;
}

interface ClassAccumulator {
  readonly direction: ProtocolDirection;
  readonly sketch: ProtocolMessageSketch;
  count: number;
  minBytes: number;
  maxBytes: number;
  totalBytes: number;
  minSegments: number;
  maxSegments: number;
  readonly positions: Map<number, { types: Set<string>; observed: number }>;
  exemplarSha256: string;
  template: Buffer | null;
}

interface StateAccumulator {
  readonly context: readonly string[];
  messageCount: number;
  sessionEnds: number;
}

interface TransitionAccumulator {
  readonly from: string;
  readonly to: string;
  readonly classId: string;
  count: number;
  sessions: number;
  lastSession: string | null;
}

const numericId = (value: string): number => Number(value.slice(1));

const stateIdOf = (index: number): string => `s${String(index)}`;
const classIdOf = (index: number): string => `c${String(index)}`;

const compareIds = (left: string, right: string): number =>
  numericId(left) - numericId(right);

/**
 * Learn one finite-state model from observed conversations.
 *
 * The alphabet is the set of observed message classes; a state is the bounded
 * suffix of classes that leads to it, which makes the machine deterministic by
 * construction. When the requested suffix length would exceed the state cap,
 * the longest suffix that fits is retained and the reduction is reported, so a
 * small model is never presented as the exact one.
 */
export const learnProtocolModel = (
  sessions: readonly ProtocolSessionFact[],
  options: LearnProtocolModelOptions,
): LearnedProtocolModel => {
  const totals = {
    sessions: sessions.length,
    messages: 0,
    request: 0,
    response: 0,
    unattributed: 0,
  };
  for (const session of sessions)
    for (const message of session.messages) {
      totals.messages += 1;
      totals[message.direction] += 1;
    }

  const classIndex = new Map<string, string>();
  const classes: ClassAccumulator[] = [];
  const admitted: { session: string; classIds: string[] }[] = [];
  let retainedMessages = 0;
  let alphabetOmitted = 0;

  for (const session of sessions) {
    if (admitted.length >= PROTOLEARN_LIMITS.maxSessions) continue;
    const classIds: string[] = [];
    let truncated = false;
    for (const message of session.messages) {
      if (truncated || retainedMessages >= PROTOLEARN_LIMITS.maxMessages)
        continue;
      const key = messageClassKey(message.direction, message.sketch);
      let classId = classIndex.get(key);
      if (classId === undefined) {
        if (classes.length >= PROTOLEARN_LIMITS.maxClasses) {
          alphabetOmitted += 1;
          truncated = true;
          continue;
        }
        classId = classIdOf(classes.length);
        classIndex.set(key, classId);
        classes.push({
          direction: message.direction,
          sketch: message.sketch,
          count: 0,
          minBytes: message.byte_length,
          maxBytes: message.byte_length,
          totalBytes: 0,
          minSegments: message.sketch.segments,
          maxSegments: message.sketch.segments,
          positions: new Map(),
          exemplarSha256: message.payload_sha256 ?? "",
          template: null,
        });
      }
      const accumulator = classes[numericId(classId)];
      if (accumulator === undefined) continue;
      accumulator.count += 1;
      accumulator.minBytes = Math.min(
        accumulator.minBytes,
        message.byte_length,
      );
      accumulator.maxBytes = Math.max(
        accumulator.maxBytes,
        message.byte_length,
      );
      accumulator.totalBytes += message.byte_length;
      accumulator.minSegments = Math.min(
        accumulator.minSegments,
        message.sketch.segments,
      );
      accumulator.maxSegments = Math.max(
        accumulator.maxSegments,
        message.sketch.segments,
      );
      for (const [position, type] of message.sketch.segment_types.entries()) {
        if (position >= PROTOLEARN_LIMITS.maxFieldPositions) break;
        const retained = accumulator.positions.get(position) ?? {
          types: new Set<string>(),
          observed: 0,
        };
        retained.types.add(type);
        retained.observed += 1;
        accumulator.positions.set(position, retained);
      }
      if (
        accumulator.template === null &&
        message.payload !== null &&
        message.payload.length > 0
      )
        accumulator.template = message.payload.subarray(
          0,
          PROTOLEARN_LIMITS.maxTemplateBytes,
        );
      classIds.push(classId);
      retainedMessages += 1;
    }
    if (classIds.length > 0) admitted.push({ session: session.session, classIds });
  }

  const buildMachines = (suffixLength: number) => {
    const stateIndex = new Map<string, string>();
    const states: StateAccumulator[] = [];
    const transitions = new Map<string, TransitionAccumulator>();
    const stateOf = (context: readonly string[]): string => {
      const signature = context.join(">");
      const existing = stateIndex.get(signature);
      if (existing !== undefined) return existing;
      const id = stateIdOf(states.length);
      stateIndex.set(signature, id);
      states.push({ context: [...context], messageCount: 0, sessionEnds: 0 });
      return id;
    };
    // A model always has its initial state, even when nothing was admitted.
    stateOf([]);
    for (const session of admitted) {
      const sequence = session.classIds;
      for (let index = 0; index < sequence.length; index += 1) {
        const from = stateOf(
          sequence.slice(Math.max(0, index - suffixLength), index),
        );
        const to = stateOf(
          sequence.slice(Math.max(0, index + 1 - suffixLength), index + 1),
        );
        const classId = sequence[index];
        if (classId === undefined) continue;
        const stateBody = states[numericId(from)];
        if (stateBody !== undefined) stateBody.messageCount += 1;
        const key = `${from}|${classId}`;
        const transition = transitions.get(key) ?? {
          from,
          to,
          classId,
          count: 0,
          sessions: 0,
          lastSession: null,
        };
        transition.count += 1;
        if (transition.lastSession !== session.session) {
          transition.sessions += 1;
          transition.lastSession = session.session;
        }
        transitions.set(key, transition);
      }
      const final = stateOf(
        sequence.slice(Math.max(0, sequence.length - suffixLength)),
      );
      const finalBody = states[numericId(final)];
      if (finalBody !== undefined) finalBody.sessionEnds += 1;
    }
    return { states, transitions };
  };

  let retainedSuffix = Math.min(
    Math.max(0, Math.floor(options.suffix_length)),
    PROTOLEARN_LIMITS.maxSuffixLength,
  );
  let machine = buildMachines(retainedSuffix);
  while (
    machine.states.length > options.max_states &&
    retainedSuffix > 0
  ) {
    retainedSuffix -= 1;
    machine = buildMachines(retainedSuffix);
  }

  const states: ProtocolState[] = machine.states.map((state, index) => ({
    state_id: stateIdOf(index),
    context: [...state.context],
    message_count: state.messageCount,
    session_ends: state.sessionEnds,
    accepting: state.sessionEnds > 0,
  }));
  const transitions: ProtocolTransition[] = [...machine.transitions.values()]
    .map((transition) => ({
      from: transition.from,
      to: transition.to,
      class_id: transition.classId,
      count: transition.count,
      sessions: transition.sessions,
    }))
    .sort(
      (left, right) =>
        compareIds(left.from, right.from) ||
        compareIds(left.class_id, right.class_id),
    );

  const templates = new Map<string, Buffer>();
  const retainedClasses: ProtocolMessageClass[] = classes.map(
    (accumulator, index) => {
      const classId = classIdOf(index);
      const template = accumulator.template;
      if (template !== null) {
        templates.set(classId, template);
        accumulator.template = null;
      }
      return {
        class_id: classId,
        direction: accumulator.direction,
        sketch: accumulator.sketch,
        message_count: accumulator.count,
        byte_length: {
          min: accumulator.minBytes,
          max: accumulator.maxBytes,
          total: accumulator.totalBytes,
        },
        segment_count: {
          min: accumulator.minSegments,
          max: accumulator.maxSegments,
        },
        positions: [...accumulator.positions.entries()]
          .sort(([left], [right]) => left - right)
          .map(([position, retained]) => ({
            position,
            types: [...retained.types].sort(),
            observed: retained.observed,
          })),
        exemplar_sha256: accumulator.exemplarSha256,
        template:
          template === null
            ? null
            : {
                file: `class-${classId}.bin`,
                bytes: template.length,
                sha256: payloadDigest(template),
              },
      };
    },
  );

  const retained = admitted.reduce(
    (total, session) => total + session.classIds.length,
    0,
  );
  const suffixReduced = retainedSuffix < options.suffix_length;
  const partial =
    retained < totals.messages ||
    admitted.length < totals.sessions ||
    alphabetOmitted > 0 ||
    suffixReduced;
  const sketchKinds = [
    ...new Set(retainedClasses.map(({ sketch }) => sketch.kind)),
  ].sort();
  return {
    sessions: {
      total: totals.sessions,
      retained: admitted.length,
      omitted: totals.sessions - admitted.length,
    },
    messages: {
      total: totals.messages,
      retained,
      omitted: totals.messages - retained,
      request: totals.request,
      response: totals.response,
      unattributed: totals.unattributed,
    },
    alphabet: {
      class_count: retainedClasses.length,
      omitted: alphabetOmitted,
      sketch_kinds: sketchKinds,
    },
    classes: retainedClasses,
    states,
    transitions,
    merge: {
      requested_suffix_length: options.suffix_length,
      retained_suffix_length: retainedSuffix,
      max_states: options.max_states,
      suffix_reduced: suffixReduced,
    },
    coverage: partial ? "partial" : "complete",
    templates,
  };
};
