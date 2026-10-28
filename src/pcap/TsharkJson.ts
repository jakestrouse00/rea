import { setImmediate as yieldToEventLoop } from "node:timers/promises";

import {
  AnalysisCancelledError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";

/** Bounds JSON decoding plus its expanded object graph before JSON.parse. */
export const TSHARK_JSON_MAX_BYTES = 8 * 1024 * 1024;
const MAX_DECODED_BYTES = 128 * 1024 * 1024;

/** One packet's selected fields, as tshark emits them: arrays of strings. */
export type TsharkPacketLayers = Readonly<Record<string, readonly string[]>>;

export interface TsharkJsonReadOptions {
  readonly operation?: string;
  readonly signal?: AbortSignal;
  /** Bytes above this bound are refused before decoding. */
  readonly maxJsonBytes?: number;
}

const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Decode one `tshark -T json` document into per-packet layer maps, owning the
 * bounds every projection shares: retained byte budget, object-graph budget,
 * nesting budget, and frame order. Callers project facts from the layers; no
 * caller re-parses the wire text.
 */
export const readTsharkPacketLayers = async (
  stdout: string,
  options: TsharkJsonReadOptions = {},
): Promise<readonly TsharkPacketLayers[]> => {
  const operation = options.operation ?? "inspect_pcap_capture";
  const signal = options.signal;
  const maxJsonBytes = options.maxJsonBytes ?? TSHARK_JSON_MAX_BYTES;
  const assertReadActive = (): void => {
    if (signal?.aborted)
      throw new AnalysisCancelledError(operation, { cause: signal.reason });
  };
  const protocolFailure = (reason: string): never => {
    throw new AnalysisProtocolError(
      `Invalid packet-capture output: ${reason}`,
      { diagnostics: { operation } },
    );
  };
  assertReadActive();
  if (Buffer.byteLength(stdout) > maxJsonBytes)
    throw new AnalysisResourceConstraintError(
      operation,
      "memory",
      "tshark JSON exceeds the bounded decoding budget",
      { max_json_bytes: maxJsonBytes },
      fixedAllowanceOptions("The tshark JSON decoding allowance", "capture"),
    );
  // The selected-field protocol has five container levels. Reject deeper
  // graphs before materializing them; quoted brackets are string data.
  let depth = 0,
    quoted = false,
    escaped = false;
  let decodedBytes = stdout.length * 2;
  for (let index = 0; index < stdout.length; index += 1) {
    if (index % 65536 === 0) {
      await yieldToEventLoop();
      assertReadActive();
    }
    const char = stdout[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') {
      quoted = true;
      decodedBytes += 64;
    } else if (char === "{" || char === "[") {
      decodedBytes += 128;
      if (++depth > 5) protocolFailure("unexpected JSON nesting");
    } else if (char === "}" || char === "]") depth -= 1;
    else if (char === ":" || char === ",") decodedBytes += 128;
    if (decodedBytes > MAX_DECODED_BYTES)
      throw new AnalysisResourceConstraintError(
        operation,
        "memory",
        "tshark JSON expansion exceeds the decoding budget",
        { max_decoded_bytes: MAX_DECODED_BYTES },
        fixedAllowanceOptions("The tshark JSON expansion allowance", "capture"),
      );
  }
  let packets: unknown;
  try {
    packets = JSON.parse(stdout) as unknown;
  } catch (cause) {
    throw new AnalysisProtocolError("tshark emitted malformed JSON", { cause });
  }
  if (!Array.isArray(packets))
    return protocolFailure("tshark packet root must be an array");
  const read: TsharkPacketLayers[] = [];
  for (let index = 0; index < packets.length; index += 1) {
    if (index % 256 === 0) {
      await yieldToEventLoop();
      assertReadActive();
    }
    const packet: unknown = packets[index];
    if (
      !object(packet) ||
      !object(packet._source) ||
      !object(packet._source.layers)
    )
      return protocolFailure(
        `packet ${String(index + 1)} lacks _source.layers`,
      );
    const layers = packet._source.layers;
    for (const [key, value] of Object.entries(layers))
      if (
        !Array.isArray(value) ||
        !value.every((item) => typeof item === "string")
      )
        return protocolFailure(
          `packet ${String(index + 1)} field ${key} must be an array of strings`,
        );
    const frame = (layers["frame.number"] as string[] | undefined) ?? [];
    if (
      frame.length !== 1 ||
      !/^\d+$/u.test(frame[0] ?? "") ||
      Number(frame[0]) !== index + 1
    )
      return protocolFailure(
        "frame inventory is missing, duplicated or out of order",
      );
    read.push(layers as Record<string, readonly string[]>);
  }
  return read;
};
