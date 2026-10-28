import { expect, test } from "vitest";

import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { payloadDigest } from "../domain/protolearn/protocolMessage.js";
import { parsePcapMessageRows } from "./PcapMessageRows.js";

const packet = (layers: Record<string, string[]>) =>
  JSON.stringify({ _source: { layers } });

const tcp = (
  frame: number,
  payload: string,
  options: { stream?: string; source?: string; destination?: string } = {},
) =>
  packet({
    "frame.number": [String(frame)],
    "frame.protocols": ["eth:ethertype:ip:tcp"],
    "ip.src": [options.source ?? "10.0.0.2"],
    "ip.dst": [options.destination ?? "10.0.0.3"],
    "tcp.srcport": [options.source === "10.0.0.3" ? "9000" : "5000"],
    "tcp.dstport": [options.source === "10.0.0.3" ? "5000" : "9000"],
    "tcp.stream": [options.stream ?? "0"],
    "tcp.payload": [payload],
  });

const hex = (value: string): string =>
  Buffer.from(value, "utf8")
    .toString("hex")
    .toUpperCase()
    .match(/.{2}/gu)
    ?.join(":") ?? "";

const conversation = () =>
  JSON.stringify([
    JSON.parse(tcp(1, hex("HELLO\n"))),
    JSON.parse(tcp(2, hex("OK\n"), { stream: "0", source: "10.0.0.3" })),
    JSON.parse(tcp(3, hex("NEXT\n"))),
    JSON.parse(tcp(4, hex("READY\n"), { stream: "0", source: "10.0.0.3" })),
  ]);

test("projects one conversation with direction from its first frame", async () => {
  const stream = await parsePcapMessageRows(conversation(), { format: "pcap" });
  expect(stream.packets).toBe(4);
  expect(stream.framesWithoutPayload).toBe(0);
  expect(stream.sessions).toHaveLength(1);
  const messages = stream.sessions[0]?.messages ?? [];
  expect(messages.map(({ direction }) => direction)).toEqual([
    "request",
    "response",
    "request",
    "response",
  ]);
  expect(messages.map(({ byte_length }) => byte_length)).toEqual([6, 3, 5, 6]);
  expect(messages[0]?.sketch).toMatchObject({
    kind: "text",
    printable_ratio: "high",
    line_terminated: true,
    segments: 1,
    segment_types: ["alpha"],
  });
  expect(messages[0]?.payload_sha256).toBe(
    payloadDigest(Buffer.from("HELLO\n", "utf8")),
  );
  expect(messages[0]?.payload?.toString("utf8")).toBe("HELLO\n");
});

test("keeps two streams as two conversations and counts payloadless frames", async () => {
  const rows = [
    JSON.parse(tcp(1, hex("A\n"), { stream: "0" })),
    JSON.parse(tcp(2, hex("B\n"), { stream: "1" })),
    JSON.parse(
      packet({
        "frame.number": ["3"],
        "frame.protocols": ["eth:ethertype:ip:tcp"],
        "ip.src": ["10.0.0.2"],
        "ip.dst": ["10.0.0.3"],
        "tcp.srcport": ["5000"],
        "tcp.dstport": ["9000"],
        "tcp.stream": ["0"],
      }),
    ),
  ];
  const stream = await parsePcapMessageRows(JSON.stringify(rows), {
    format: "pcapng",
  });
  expect(stream.format).toBe("pcapng");
  expect(stream.sessions.map(({ session }) => session)).toEqual([
    "tcp-stream:0",
    "tcp-stream:1",
  ]);
  expect(stream.framesWithoutPayload).toBe(1);
});

test("groups a flow with no stream id by its endpoint pair", async () => {
  const rows = [
    JSON.parse(
      packet({
        "frame.number": ["1"],
        "frame.protocols": ["eth:ethertype:ip:udp:data"],
        "ip.src": ["10.0.0.9"],
        "ip.dst": ["10.0.0.2"],
        "udp.srcport": ["5353"],
        "udp.dstport": ["53"],
        "data.data": [hex("PING\n")],
      }),
    ),
    JSON.parse(
      packet({
        "frame.number": ["2"],
        "frame.protocols": ["eth:ethertype:ip:udp:data"],
        "ip.src": ["10.0.0.2"],
        "ip.dst": ["10.0.0.9"],
        "udp.srcport": ["53"],
        "udp.dstport": ["5353"],
        "data.data": [hex("PONG\n")],
      }),
    ),
  ];
  const stream = await parsePcapMessageRows(JSON.stringify(rows), {
    format: "pcap",
  });
  expect(stream.sessions).toHaveLength(1);
  expect(
    stream.sessions[0]?.messages.map(({ direction }) => direction),
  ).toEqual(["request", "response"]);
});

test("refuses a payload field that is not colon-separated hex", async () => {
  const rows = [
    JSON.parse(
      packet({
        "frame.number": ["1"],
        "frame.protocols": ["eth:ethertype:ip:tcp"],
        "ip.src": ["10.0.0.2"],
        "ip.dst": ["10.0.0.3"],
        "tcp.srcport": ["5000"],
        "tcp.dstport": ["9000"],
        "tcp.stream": ["0"],
        "tcp.payload": ["not hex"],
      }),
    ),
  ];
  await expect(
    parsePcapMessageRows(JSON.stringify(rows), { format: "pcap" }),
  ).rejects.toBeInstanceOf(AnalysisProtocolError);
});

test("refuses a frame inventory that is out of order", async () => {
  const rows = [JSON.parse(tcp(2, hex("A\n"))), JSON.parse(tcp(1, hex("B\n")))];
  await expect(
    parsePcapMessageRows(JSON.stringify(rows), { format: "pcap" }),
  ).rejects.toBeInstanceOf(AnalysisProtocolError);
});

test("refuses a packet root that is not an array", async () => {
  await expect(
    parsePcapMessageRows(JSON.stringify({ packets: [] }), { format: "pcap" }),
  ).rejects.toBeInstanceOf(AnalysisProtocolError);
});

test("cancels a long projection when the caller aborts", async () => {
  const controller = new AbortController();
  controller.abort(new Error("caller stopped"));
  await expect(
    parsePcapMessageRows(conversation(), {
      format: "pcap",
      signal: controller.signal,
    }),
  ).rejects.toThrow(/cancel/i);
});
