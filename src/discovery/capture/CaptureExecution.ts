import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  runDiscoveryObservation,
  type DiscoveryProcessLauncher,
} from "../DiscoveryCommand.js";
import {
  captureResultSchemas,
  CAPTURE_OPERATION,
  type CaptureInput,
  type CaptureReport,
} from "./CaptureAnalysis.js";

/** How much extra wall time the child gets to flush after the window ends. */
const TERMINATION_GRACE_MS = 2_000;

/** Count of leading bytes validated against the pcap/pcapng magics. */
const MAGIC_BYTES = 32;

/** Ceiling of the retained child stderr tail. */
const STDERR_TAIL_CHARS = 2_000;

/**
  Classify the leading bytes of a capture file. Classic pcap is recognized in
  its four byte orders (microsecond and nanosecond, each endianness); pcapng
  by its block-type magic.
 */
export const formatFromMagic = (
  head: Uint8Array,
): "pcap" | "pcapng" | "unknown" => {
  if (head.length < 4) return "unknown";
  const view = Buffer.from(head);
  const asBigEndian = view.readUInt32BE(0);
  const asLittleEndian = view.readUInt32LE(0);
  if (asBigEndian === 0x0a0d0d0a) return "pcapng";
  const pcapMagics = [0xa1b2c3d4, 0xa1b23c4d];
  if (pcapMagics.includes(asBigEndian) || pcapMagics.includes(asLittleEndian))
    return "pcap";
  return "unknown";
};

const readHead = async (path: string): Promise<Buffer> => {
  const handle = await open(path, "r");
  try {
    const head = Buffer.alloc(MAGIC_BYTES);
    const { bytesRead } = await handle.read(head, 0, MAGIC_BYTES, 0);
    return head.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
};

/**
  Hash the retained output file with a bounded streaming read. A neutral
  shared file-digest helper lives in the application layer, which a provider
  adapter must not import from, so this lane owns a minimal copy.
 */
const sha256File = async (path: string): Promise<string> => {
  const handle = await open(path, "r");
  try {
    const hash = createHash("sha256");
    const chunk = Buffer.alloc(1024 * 1024);
    for (;;) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.byteLength, null);
      if (bytesRead === 0) break;
      hash.update(chunk.subarray(0, bytesRead));
    }
    return hash.digest("hex");
  } finally {
    await handle.close();
  }
};

const stderrTail = (stderr: string): string =>
  stderr.trim().split("\n").join(" | ").slice(-STDERR_TAIL_CHARS);

/**
  Run the caller-provided capture program for the requested window, terminate
  it, and report the retained output file. The program receives exactly one
  argument, the output path; the caller's command is preconfigured with its
  own interface and flags. REA never deletes the output file: on an early
  nonzero exit, an unwritten file, or unrecognized magic the bytes stay on
  disk for caller inspection.
 */
export const executePacketCapture = async (
  captureCommand: string,
  input: CaptureInput,
  signal?: AbortSignal,
  launcher?: DiscoveryProcessLauncher,
): Promise<Result<CaptureReport, AnalysisError>> => {
  if (input.authorize_capture !== true)
    return err(
      new AnalysisInputError(CAPTURE_OPERATION, {
        userMessage:
          "The capture requires the caller's explicit authorization: pass authorize_capture: true to acknowledge the packets and RxFrames this capture originates from this host",
      }),
    );
  const command = (input.command ?? captureCommand).trim();
  if (command === "")
    return err(
      new AnalysisInputError(CAPTURE_OPERATION, {
        userMessage: "The capture command is not configured for this host",
      }),
    );
  const capture_started_at = new Date().toISOString();
  const ran = await runDiscoveryObservation(
    CAPTURE_OPERATION,
    command,
    [input.output_path],
    {
      timeoutMs: input.duration_seconds * 1000 + TERMINATION_GRACE_MS,
    },
    signal,
    launcher,
  );
  if (!ran.ok) return ran;
  if (
    !ran.value.timed_out &&
    ran.value.exit_code !== null &&
    ran.value.exit_code !== 0
  )
    return err(
      new AnalysisProtocolError(
        `the capture command exited ${String(ran.value.exit_code)} before the window elapsed; the output file was not deleted and any bytes written remain at ${input.output_path}: ${stderrTail(ran.value.stderr)}`,
      ),
    );
  try {
    const stats = await open(input.output_path, "r").then(async (handle) => {
      try {
        return await handle.stat();
      } finally {
        await handle.close();
      }
    });
    if (!stats.isFile()) return err(captureMissing(input.output_path));
    const head = await readHead(input.output_path);
    const sha256 = await sha256File(input.output_path);
    const parsed = captureResultSchemas[CAPTURE_OPERATION].safeParse({
      output_path: input.output_path,
      file_bytes: stats.size,
      sha256,
      format: formatFromMagic(head),
      magic_hex: head.subarray(0, 4).toString("hex"),
      capture_started_at,
      duration_seconds: input.duration_seconds,
      command_stderr_tail: stderrTail(ran.value.stderr),
    });
    if (!parsed.success)
      return err(
        new AnalysisProtocolError(
          `the capture report did not match its contract: ${parsed.error.message}`,
        ),
      );
    return ok(parsed.data);
  } catch (cause: unknown) {
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError(CAPTURE_OPERATION, {
          cause: signal.reason,
        }),
      );
    return err(captureMissing(input.output_path, cause));
  }
};

const captureMissing = (outputPath: string, cause?: unknown): AnalysisError =>
  new AnalysisProtocolError(
    `the capture program wrote no readable file at ${outputPath}; the path was left in place and REA did not delete it`,
    { cause },
  );
