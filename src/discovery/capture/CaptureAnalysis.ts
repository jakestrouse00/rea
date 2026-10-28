import { z } from "zod";
import { digestSchema } from "../../domain/digests.js";
import { absoluteLocalPathStringSchema } from "../../domain/localPath.js";

export const CAPTURE_OPERATION = "capture_radio_packets" as const;

/** Environment key whose value is the caller-supplied capture program. */
export const PACKET_CAPTURE_COMMAND_ENV = "REA_PACKET_CAPTURE_COMMAND";

/** Remediation for the absence of PACKET_CAPTURE_COMMAND_ENV. */
export const CAPTURE_COMMAND_REMEDIATION = `Set ${PACKET_CAPTURE_COMMAND_ENV} to the absolute path of a caller-provided capture program (for example a sudo-configured tcpdump wrapper script) that is preconfigured with its own interface and flags and writes its output to the single argument REA appends, which is the output path. A packet capture originates packets and RxFrames from this host and needs caller-provided privileges: REA never installs a capture binary and never elevates privileges itself.`;

/** Draft input schemas for the packet-capture acquisition lane. */
export const captureInputSchemas = {
  [CAPTURE_OPERATION]: z.strictObject({
    output_path: absoluteLocalPathStringSchema
      .min(5)
      .regex(/\.pcap(ng)?$/u, "must end in .pcap or .pcapng")
      .describe(
        "Absolute path where the capture program writes the capture file, preserved exactly as given and never deleted, even when validation fails",
      ),
    duration_seconds: z
      .number()
      .int()
      .min(1)
      .max(60)
      .default(10)
      .describe("How long the capture program runs before REA terminates it"),
    authorize_capture: z
      .literal(true)
      .describe(
        "Must be true: acknowledge that the capture originates packets and RxFrames from this host and requires caller-provided privileges",
      ),
    command: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Absolute capture command used for this invocation instead of REA_PACKET_CAPTURE_COMMAND",
      ),
  }),
} as const;

export type CaptureOperation = keyof typeof captureInputSchemas;

export type CaptureRequest = {
  [Name in CaptureOperation]: {
    operation: Name;
    input: z.infer<(typeof captureInputSchemas)[Name]>;
  };
}[CaptureOperation];

export type CaptureInput = z.infer<
  (typeof captureInputSchemas)[CaptureOperation]
>;

/** Validate operation and input together so their types remain correlated. */
export const captureRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal(CAPTURE_OPERATION),
    input: captureInputSchemas[CAPTURE_OPERATION],
  }),
]) as z.ZodType<CaptureRequest>;

export const captureResultSchemas = {
  [CAPTURE_OPERATION]: z.strictObject({
    output_path: absoluteLocalPathStringSchema,
    file_bytes: z.number().int().nonnegative(),
    sha256: digestSchema,
    format: z.enum(["pcap", "pcapng", "unknown"]),
    magic_hex: z.string().min(1),
    capture_started_at: z.string().min(1),
    duration_seconds: z.number().int().min(1),
    command_stderr_tail: z.string(),
  }),
} as const;

export type CaptureReport = z.infer<
  (typeof captureResultSchemas)[CaptureOperation]
>;
