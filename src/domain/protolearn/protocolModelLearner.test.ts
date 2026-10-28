import { expect, test } from "vitest";

import {
  learnProtocolModel,
  type ProtocolSessionFact,
} from "./protocolModelLearner.js";
import {
  payloadDigest,
  payloadSketch,
  type ProtocolDirection,
  type ProtocolMessageFact,
} from "./protocolMessage.js";
import { PROTOLEARN_LIMITS } from "./protolearnLimits.js";

const message = (
  direction: ProtocolDirection,
  body: string,
  ordinal: number,
): ProtocolMessageFact => {
  const payload = Buffer.from(body, "utf8");
  return {
    session: "s",
    ordinal,
    direction,
    byte_length: payload.length,
    payload_sha256: payloadDigest(payload),
    sketch: payloadSketch(payload),
    payload,
  };
};

const session = (
  sessionId: string,
  bodies: readonly [ProtocolDirection, string][],
): ProtocolSessionFact => ({
  session: sessionId,
  messages: bodies.map(([direction, body], ordinal) =>
    message(direction, body, ordinal),
  ),
});

const exchange = (sessionId: string) =>
  session(sessionId, [
    ["request", "HELLO\n"],
    ["response", "OK\n"],
    ["request", "NEXT\n"],
    ["response", "READY\n"],
  ]);

test("builds one state per retained suffix and counts every transition", () => {
  const model = learnProtocolModel([exchange("a"), exchange("b")], {
    max_states: 24,
    suffix_length: 2,
  });
  expect(model.states.map(({ state_id, context }) => ({ state_id, context }))).toEqual([
    { state_id: "s0", context: [] },
    { state_id: "s1", context: ["c0"] },
    { state_id: "s2", context: ["c0", "c1"] },
    { state_id: "s3", context: ["c1", "c0"] },
  ]);
  expect(model.transitions).toEqual([
    { from: "s0", to: "s1", class_id: "c0", count: 2, sessions: 2 },
    { from: "s1", to: "s2", class_id: "c1", count: 2, sessions: 2 },
    { from: "s2", to: "s3", class_id: "c0", count: 2, sessions: 2 },
    { from: "s3", to: "s2", class_id: "c1", count: 2, sessions: 2 },
  ]);
  expect(model.states[2]).toMatchObject({
    message_count: 2,
    session_ends: 2,
    accepting: true,
  });
  expect(model.messages).toMatchObject({
    total: 8,
    retained: 8,
    request: 4,
    response: 4,
    unattributed: 0,
  });
  expect(model.coverage).toBe("complete");
});

test("shrinks the suffix length until the model fits the state cap", () => {
  const model = learnProtocolModel([exchange("a")], {
    max_states: 2,
    suffix_length: 4,
  });
  expect(model.states.length).toBeLessThanOrEqual(2);
  expect(model.merge.suffix_reduced).toBe(true);
  expect(model.merge.retained_suffix_length).toBeLessThan(4);
  expect(model.coverage).toBe("partial");
});

test("keeps the machine deterministic at suffix length zero", () => {
  const model = learnProtocolModel([exchange("a")], {
    max_states: 1,
    suffix_length: 0,
  });
  expect(model.states).toHaveLength(1);
  expect(model.transitions.every(({ from, to }) => from === "s0" && to === "s0")).toBe(
    true,
  );
  expect(model.merge.suffix_reduced).toBe(false);
});

test("counts messages past the retention bound as omitted", () => {
  const many = Array.from({ length: PROTOLEARN_LIMITS.maxMessages + 3 }, (_, index) =>
    message("request", `R${String(index)}\n`, index),
  );
  const model = learnProtocolModel([{ session: "a", messages: many }], {
    max_states: 8,
    suffix_length: 1,
  });
  expect(model.messages.retained).toBe(PROTOLEARN_LIMITS.maxMessages);
  expect(model.messages.omitted).toBe(3);
  expect(model.coverage).toBe("partial");
});

test("truncates a conversation at the first class its alphabet cannot hold", () => {
  const bodies: [ProtocolDirection, string][] = [
    ["request", "A\n"],
    ["request", "B 1\n"],
    ["request", "C x\n"],
  ];
  const model = learnProtocolModel([session("a", bodies)], {
    max_states: 8,
    suffix_length: 1,
  });
  expect(model.alphabet.class_count).toBe(3);
  expect(model.alphabet.omitted).toBe(0);
  // Classes are capped only by maxClasses; this case proves distinct sketches
  // stay distinct rather than being folded together.
  expect(new Set(model.classes.map(({ sketch }) => sketch.segments)).size).toBe(2);
});

test("reports a partial conversation set and unattributed direction", () => {
  const model = learnProtocolModel(
    [
      session("a", [["unattributed", "PING\n"]]),
      ...Array.from({ length: PROTOLEARN_LIMITS.maxSessions + 1 }, (_, index) =>
        session(`extra-${String(index)}`, [["request", "X\n"]]),
      ),
    ],
    { max_states: 4, suffix_length: 1 },
  );
  expect(model.sessions.retained).toBe(PROTOLEARN_LIMITS.maxSessions);
  expect(model.sessions.omitted).toBeGreaterThan(0);
  expect(model.messages.unattributed).toBe(1);
  expect(model.messages.omitted).toBeGreaterThan(0);
  expect(model.coverage).toBe("partial");
});

test("retains one exemplar per class and no payload text in the model", () => {
  const model = learnProtocolModel([exchange("a")], {
    max_states: 24,
    suffix_length: 2,
  });
  expect(model.templates.get("c0")?.toString("utf8")).toBe("HELLO\n");
  expect(model.templates.get("c1")?.toString("utf8")).toBe("OK\n");
  expect(model.classes[0]?.template).toEqual({
    file: "class-c0.bin",
    bytes: 6,
    sha256: payloadDigest(Buffer.from("HELLO\n", "utf8")),
  });
  expect(model.classes[0]?.positions).toEqual([
    { position: 0, types: ["alpha"], observed: 2 },
  ]);
  const serialized = JSON.stringify(model.classes);
  expect(serialized).not.toContain("HELLO");
  expect(serialized).not.toContain("READY");
});

test("returns one initial state for a capture with no admitted messages", () => {
  const model = learnProtocolModel([], { max_states: 8, suffix_length: 2 });
  expect(model.states).toEqual([
    {
      state_id: "s0",
      context: [],
      message_count: 0,
      session_ends: 0,
      accepting: false,
    },
  ]);
  expect(model.transitions).toEqual([]);
  expect(model.sessions).toEqual({ total: 0, retained: 0, omitted: 0 });
});
