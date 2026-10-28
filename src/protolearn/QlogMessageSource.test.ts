import { expect, test } from "vitest";

import { qlogMessageSessions } from "./QlogMessageSource.js";

const qlog = (
  events: readonly unknown[],
  vantage: "client" | "server" | null = "server",
) =>
  JSON.stringify({
    qlog_format: "JSON",
    qlog_version: "0.3",
    traces: [
      {
        common_fields: { ODCID: "odcid-1" },
        vantage_point: vantage === null ? {} : { name: "aioquic", type: vantage },
        events,
      },
    ],
  });

const packet = (
  name: "transport:packet_sent" | "transport:packet_received",
  packetType: string,
  frames: readonly Record<string, unknown>[],
  length = 64,
) => ({
  name,
  time: 1,
  data: {
    header: { packet_type: packetType, packet_number: 1 },
    raw: { length },
    frames,
  },
});

const streamFrame = { frame_type: "stream", stream_id: 0, offset: 0, length: 10 };

test("maps packet sends and receives onto directions from the vantage point", () => {
  const { sessions, traces, eventsIgnored } = qlogMessageSessions(
    qlog([
      packet("transport:packet_received", "initial", [
        { frame_type: "crypto", offset: 0, length: 20 },
      ]),
      packet("transport:packet_sent", "handshake", [
        { frame_type: "crypto", offset: 0, length: 30 },
        { frame_type: "ack", packet_number: 1 },
      ]),
      packet("transport:packet_sent", "1RTT", [streamFrame]),
      { name: "recovery:packet_lost", time: 2, data: { packet_number: 1 } },
    ]),
    [],
  );
  expect(traces).toBe(1);
  expect(eventsIgnored).toBe(1);
  const messages = sessions[0]?.messages ?? [];
  expect(messages.map(({ direction }) => direction)).toEqual([
    "request",
    "response",
    "response",
  ]);
  expect(messages.map(({ byte_length }) => byte_length)).toEqual([64, 64, 64]);
  expect(messages[1]?.sketch.segment_types).toEqual([
    "handshake",
    "ack",
    "crypto",
  ]);
  expect(messages[2]?.sketch).toEqual({
    kind: "quic-packet",
    printable_ratio: "unknown",
    line_terminated: false,
    segments: 1,
    segment_types: ["one_rtt", "stream"],
    examined_bytes: 0,
  });
  expect(messages.every(({ payload }) => payload === null)).toBe(true);
});

test("labels a client vantage point the other way round", () => {
  const { sessions } = qlogMessageSessions(
    qlog(
      [
        packet("transport:packet_sent", "initial", []),
        packet("transport:packet_received", "1RTT", [streamFrame]),
      ],
      "client",
    ),
    [],
  );
  expect(sessions[0]?.messages.map(({ direction }) => direction)).toEqual([
    "request",
    "response",
  ]);
});

test("keeps an unknown vantage point unattributed instead of guessing", () => {
  const { sessions } = qlogMessageSessions(
    qlog([packet("transport:packet_sent", "1RTT", [streamFrame])], null),
    [],
  );
  expect(sessions[0]?.messages[0]?.direction).toBe("unattributed");
});

test("falls back to frame lengths when the raw packet length is absent", () => {
  const event = {
    name: "transport:packet_sent",
    time: 1,
    data: {
      header: { packet_type: "1RTT" },
      frames: [
        { frame_type: "stream", length: 12 },
        { frame_type: "ping" },
      ],
    },
  };
  const { sessions } = qlogMessageSessions(qlog([event]), []);
  expect(sessions[0]?.messages[0]?.byte_length).toBe(12);
  expect(sessions[0]?.messages[0]?.sketch.segments).toBe(2);
});

test("maps an unknown packet or frame type onto one bounded token", () => {
  const { sessions } = qlogMessageSessions(
    qlog([packet("transport:packet_sent", "0x99", [streamFrame])]),
    [],
  );
  expect(sessions[0]?.messages[0]?.sketch.segment_types).toEqual([
    "other",
    "stream",
  ]);
});

test("drops an event whose name an explicit sensitive value redacted", () => {
  const text = qlog([
    { name: "transport:packet_sent", time: 1, data: { header: { packet_type: "1RTT" } } },
    packet("transport:packet_sent", "initial", []),
  ]);
  const { sessions, eventsIgnored } = qlogMessageSessions(text, [
    "transport:packet_sent",
  ]);
  expect(eventsIgnored).toBe(2);
  expect(sessions).toEqual([]);
});

test("refuses a qlog document outside the owned decoder profile", () => {
  expect(() =>
    qlogMessageSessions(JSON.stringify({ qlog_format: "JSON" }), []),
  ).toThrow();
});
