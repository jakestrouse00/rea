import type { ProtocolSessionFact } from "../domain/protolearn/protocolModelLearner.js";
import {
  payloadDigest,
  payloadSketch,
  type ProtocolDirection,
  type ProtocolMessageFact,
} from "../domain/protolearn/protocolMessage.js";
import { PROTOLEARN_LIMITS } from "../domain/protolearn/protolearnLimits.js";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { readTsharkPacketLayers } from "./TsharkJson.js";

/** Fields the message projection asks tshark for. */
export const PCAP_MESSAGE_FIELDS = [
  "frame.number",
  "frame.len",
  "frame.protocols",
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "tcp.srcport",
  "tcp.dstport",
  "udp.srcport",
  "udp.dstport",
  "tcp.stream",
  "udp.stream",
  "tcp.payload",
  "udp.payload",
  "data.data",
] as const;

/** Messages one capture yields, with what the projection could not use. */
export interface PcapMessageStream {
  readonly sessions: readonly ProtocolSessionFact[];
  readonly format: "pcap" | "pcapng" | "other";
  readonly packets: number;
  /** Frames that carried no dissected payload, so they are not messages. */
  readonly framesWithoutPayload: number;
  /** Messages past the retention bound; the model reports them as omitted. */
  readonly messagesOmitted: number;
}

const HEX_PAYLOAD = /^[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2})*$/u;

export const pcapCaptureFormat = (
  fileType: string | null | undefined,
): PcapMessageStream["format"] => {
  switch (fileType) {
    case "pcap":
    case "pcapng":
      return fileType;
    default:
      return "other";
  }
};

const first = (values: readonly string[]): string | undefined => {
  for (const value of values) if (value !== "") return value;
  return undefined;
};

const parsePayloadHex = (hex: string): Buffer => {
  if (!HEX_PAYLOAD.test(hex))
    throw new AnalysisProtocolError(
      "Invalid packet-capture output: a payload field is not colon-separated hex",
    );
  return Buffer.from(hex.replaceAll(":", ""), "hex");
};

/**
 * Project one tshark document into conversation messages.
 *
 * Direction is attributed from the first frame each flow shows: whichever
 * endpoint speaks first is treated as the requester for that flow, so a
 * server-speaks-first protocol is labelled from its greeting rather than
 * guessed from ports.
 */
export const parsePcapMessageRows = async (
  stdout: string,
  options: {
    readonly format: PcapMessageStream["format"];
    readonly signal?: AbortSignal;
  },
): Promise<PcapMessageStream> => {
  const read = await readTsharkPacketLayers(stdout, {
    operation: "learn_protocol_model",
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  const flows = new Map<
    string,
    { readonly sender: string | null; messages: ProtocolMessageFact[] }
  >();
  let framesWithoutPayload = 0;
  let messagesOmitted = 0;
  let admitted = 0;
  const flowOrder: string[] = [];
  for (const layers of read) {
    const field = (name: string): readonly string[] => layers[name] ?? [];
    const srcAddress = first(field("ip.src")) ?? first(field("ipv6.src"));
    const dstAddress = first(field("ip.dst")) ?? first(field("ipv6.dst"));
    const tcpStream = first(field("tcp.stream"));
    const udpStream = first(field("udp.stream"));
    const transport =
      tcpStream !== undefined
        ? { name: "tcp", stream: tcpStream }
        : udpStream !== undefined
          ? { name: "udp", stream: udpStream }
          : null;
    const srcPort =
      first(field("tcp.srcport")) ?? first(field("udp.srcport")) ?? "";
    const dstPort =
      first(field("tcp.dstport")) ?? first(field("udp.dstport")) ?? "";
    const payloadHex =
      first(field("tcp.payload")) ??
      first(field("udp.payload")) ??
      first(field("data.data"));
    if (payloadHex === undefined) {
      framesWithoutPayload += 1;
      continue;
    }
    if (admitted >= PROTOLEARN_LIMITS.maxMessages) {
      messagesOmitted += 1;
      continue;
    }
    const payload = parsePayloadHex(payloadHex);
    if (payload.length === 0) {
      framesWithoutPayload += 1;
      continue;
    }
    const sender =
      srcAddress === undefined
        ? null
        : `${srcAddress}:${srcPort}`;
    const endpoints =
      srcAddress === undefined || dstAddress === undefined
        ? null
        : [srcAddress, dstAddress].sort().join("|") +
          `/${[srcPort, dstPort].sort().join("|")}`;
    const flowKey =
      transport === null
        ? `flow:${endpoints ?? "unknown"}`
        : `${transport.name}-stream:${transport.stream}`;
    let flow = flows.get(flowKey);
    if (flow === undefined) {
      flow = { sender, messages: [] };
      flows.set(flowKey, flow);
      flowOrder.push(flowKey);
    }
    const direction: ProtocolDirection =
      sender === null || flow.sender === null
        ? "unattributed"
        : sender === flow.sender
          ? "request"
          : "response";
    const examined = payload.subarray(0, PROTOLEARN_LIMITS.maxPayloadBytes);
    flow.messages.push({
      session: flowKey,
      ordinal: flow.messages.length,
      direction,
      byte_length: payload.length,
      payload_sha256: payloadDigest(payload),
      sketch: payloadSketch(examined),
      payload: examined,
    });
    admitted += 1;
  }
  const sessions = flowOrder.flatMap((key) => {
    const flow = flows.get(key);
    return flow === undefined || flow.messages.length === 0
      ? []
      : [{ session: key, messages: flow.messages }];
  });
  return {
    sessions,
    format: options.format,
    packets: read.length,
    framesWithoutPayload,
    messagesOmitted,
  };
};
