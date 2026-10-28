import type { ProtocolSessionFact } from "../domain/protolearn/protocolModelLearner.js";
import type {
  ProtocolDirection,
  ProtocolMessageFact,
  ProtocolMessageSketch,
} from "../domain/protolearn/protocolMessage.js";
import { PROTOLEARN_LIMITS } from "../domain/protolearn/protolearnLimits.js";
import { decodeQlogCapture } from "../browser/history/QlogCapture.js";

/** qlog packet types, mapped onto REA's bounded segment-token vocabulary. */
const PACKET_TYPES: Readonly<Record<string, string>> = {
  initial: "initial",
  handshake: "handshake",
  "0RTT": "zero_rtt",
  "1RTT": "one_rtt",
  retry: "retry",
  version_negotiation: "version_negotiation",
  stateless_reset: "stateless_reset",
};

/** qlog frame types REA names; anything else stays an undifferentiated token. */
const FRAME_TYPES = new Set([
  "padding",
  "ping",
  "ack",
  "reset_stream",
  "stop_sending",
  "crypto",
  "new_token",
  "stream",
  "max_data",
  "max_stream_data",
  "max_streams",
  "data_blocked",
  "stream_data_blocked",
  "streams_blocked",
  "new_connection_id",
  "retire_connection_id",
  "path_challenge",
  "path_response",
  "connection_close",
  "handshake_done",
  "datagram",
  "ack_frequency",
  "immediate_ack",
]);

const PACKET_EVENTS = new Set([
  "transport:packet_sent",
  "transport:packet_received",
]);

export interface QlogMessageSourceResult {
  readonly sessions: readonly ProtocolSessionFact[];
  readonly traces: number;
  /** Events that are not packet sends or receives, or that lost their name. */
  readonly eventsIgnored: number;
  readonly limitations: readonly string[];
}

const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const directionOf = (
  vantage: "client" | "server" | null,
  eventName: string,
): ProtocolDirection => {
  const sent = eventName === "transport:packet_sent";
  if (vantage === "server") return sent ? "response" : "request";
  if (vantage === "client") return sent ? "request" : "response";
  return "unattributed";
};

const frameToken = (value: unknown): string =>
  typeof value === "string" && FRAME_TYPES.has(value) ? value : "other";

const packetToken = (value: unknown): string =>
  typeof value === "string" ? (PACKET_TYPES[value] ?? "other") : "other";

const messageLength = (data: Record<string, unknown>): number => {
  const raw = object(data["raw"]) ? data["raw"] : undefined;
  if (raw !== undefined && typeof raw["length"] === "number")
    return Math.max(0, Math.trunc(raw["length"]));
  const frames = Array.isArray(data["frames"]) ? data["frames"] : [];
  let total = 0;
  for (const frame of frames)
    if (object(frame) && typeof frame["length"] === "number")
      total += Math.max(0, Math.trunc(frame["length"]));
  return total;
};

/**
 * Turn one decoded qlog capture into QUIC packet messages.
 *
 * The capture decoder owns the JSON profile, redaction, and numeric fidelity;
 * this projection reads only packet direction, packet type, frame types, and
 * lengths, so no QUIC payload byte or header value becomes Evidence.
 */
export const qlogMessageSessions = (
  text: string,
  sensitiveValues: readonly string[],
): QlogMessageSourceResult => {
  const decoded = decodeQlogCapture(text, sensitiveValues);
  if (!("qlog" in decoded))
    throw new Error("The capture decoder returned no qlog facts");
  const traces = decoded.qlog.traces;
  const offsets: number[] = [];
  let offset = 0;
  for (const trace of traces) {
    offsets.push(offset);
    offset += trace.event_count;
  }
  const sessions: ProtocolSessionFact[] = [];
  let eventsIgnored = 0;
  for (const [traceIndex, trace] of traces.entries()) {
    const traceOffset = offsets[traceIndex] ?? 0;
    const messages: ProtocolMessageFact[] = [];
    for (let eventIndex = 0; eventIndex < trace.event_count; eventIndex += 1) {
      const record = decoded.records[traceOffset + eventIndex];
      const event = record?.reported;
      if (!object(event) || typeof event["name"] !== "string") {
        eventsIgnored += 1;
        continue;
      }
      const name = event["name"];
      if (!PACKET_EVENTS.has(name)) {
        eventsIgnored += 1;
        continue;
      }
      const data = object(event["data"]) ? event["data"] : {};
      const frames = Array.isArray(data["frames"]) ? data["frames"] : [];
      const frameTokens = [
        ...new Set(frames.map((frame) =>
          object(frame) ? frameToken(frame["frame_type"]) : "other",
        )),
      ].sort();
      const header = object(data["header"]) ? data["header"] : {};
      const byteLength = messageLength(data);
      const sketch: ProtocolMessageSketch = {
        kind: "quic-packet",
        printable_ratio: "unknown",
        line_terminated: false,
        segments: frames.length,
        segment_types: [packetToken(header["packet_type"]), ...frameTokens].slice(
          0,
          PROTOLEARN_LIMITS.maxSegmentTypes,
        ),
        examined_bytes: 0,
      };
      messages.push({
        session: `qlog-trace-${String(traceIndex)}`,
        ordinal: messages.length,
        direction: directionOf(trace.vantage_point, name),
        byte_length: byteLength,
        payload_sha256: null,
        sketch,
        payload: null,
      });
    }
    if (messages.length > 0)
      sessions.push({
        session: `qlog-trace-${String(traceIndex)}`,
        messages,
      });
  }
  return {
    sessions,
    traces: traces.length,
    eventsIgnored,
    limitations: [
      "qlog records packet and frame facts, not payload bytes: a model learned from qlog has no message templates and cannot feed export_protocol_grammar",
      ...(eventsIgnored > 0
        ? [
            `${String(eventsIgnored)} qlog event(s) are not packet sends or receives, are redacted, or are not part of the selected profile`,
          ]
        : []),
    ],
  };
};
