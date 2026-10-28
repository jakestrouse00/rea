import { z } from "zod";

/**
 * Input draft for list_serial_ports. The integrator embeds this in
 * discoveryAnalysis.ts; until then this module keeps the draft self-contained.
 */
export const listSerialPortsInputSchema = z.strictObject({});

export type ListSerialPortsInput = z.infer<typeof listSerialPortsInputSchema>;

/** Baud rates stty accepts on this lane; callers select from these only. */
export const SERIAL_BAUD_RATES = [
  1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200,
] as const;

const baudRateSchema = z
  .union(SERIAL_BAUD_RATES.map((rate) => z.literal(rate)))
  .default(9600);

/**
 * Input draft for observe_serial_port. The device path is read-only: the
 * provider opens it O_RDONLY|O_NOCTTY|O_NONBLOCK and never writes a byte.
 */
export const observeSerialPortInputSchema = z.strictObject({
  device_path: z
    .string()
    .min(8)
    .max(128)
    .regex(
      /^\/dev\/(cu|tty)\.[^/]+$/u,
      "Use an absolute /dev/cu.* or /dev/tty.* device node path",
    )
    .describe("Serial device node whose receive side is observed"),
  duration_seconds: z
    .number()
    .int()
    .min(1)
    .max(30)
    .default(5)
    .describe("Receive observation window in seconds"),
  baud_rate: baudRateSchema.describe(
    "Baud rate stty configures before the receive window opens",
  ),
});

export type ObserveSerialPortInput = z.infer<
  typeof observeSerialPortInputSchema
>;

/** One macOS device node as the host reports it, unknowns null. */
export interface SerialPortRow {
  readonly device_path: string | null;
  readonly name: string | null;
  readonly interface_type: string | null;
  readonly description: string | null;
  readonly in_use: boolean | null;
}

/** Resolved tool paths echoed into results for provenance. */
export interface SerialToolset {
  readonly system_profiler: string | null;
  readonly stty: string | null;
}

/** Serial stop reason "byte_bound" joins deadline, close, read and cancel. */
export type SerialStopReason =
  | "deadline"
  | "closed"
  | "read_error"
  | "byte_bound"
  | "cancelled";

/** One stty-argument set as this lane runs it; stty applies settings left to right. */
export const serialSttyArguments = (
  devicePath: string,
  baudRate: number,
): readonly string[] => [
  "-f",
  devicePath,
  String(baudRate),
  "cs8",
  "-cstopb",
  "-parenb",
];

/**
 * Result drafts for the two wired-serial operations. The integrator embeds
 * these in discoveryResultSchemas.ts; until then these modules keep the
 * drafts self-contained.
 */
export const serialResultSchemas = {
  list_serial_ports: z.strictObject({
    tools: z.strictObject({
      system_profiler: z.string().min(1).nullable(),
      stty: z.string().min(1).nullable(),
    }),
    ports: z.array(
      z.strictObject({
        device_path: z.string().min(1).nullable(),
        name: z.string().min(1).nullable(),
        interface_type: z.string().min(1).nullable(),
        description: z.string().min(1).nullable(),
        in_use: z.boolean().nullable(),
      }),
    ),
    unmatched_port_names: z.array(z.string().min(1)),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  observe_serial_port: z.strictObject({
    tools: z.strictObject({
      system_profiler: z.string().min(1).nullable(),
      stty: z.string().min(1).nullable(),
    }),
    device_path: z.string().min(1),
    baud_rate: z.number().int(),
    duration_seconds: z.number().int().positive(),
    bytes_observed: z.number().int().nonnegative(),
    hex_preview: z.string().min(1).nullable(),
    printable_preview: z.string().min(1).nullable(),
    stop_reason: z.enum([
      "deadline",
      "closed",
      "read_error",
      "byte_bound",
      "cancelled",
    ]),
    stop_detail: z.string().min(1).nullable(),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
} as const;

export type SerialListResult = z.infer<
  (typeof serialResultSchemas)["list_serial_ports"]
>;

export type SerialObserveResult = z.infer<
  (typeof serialResultSchemas)["observe_serial_port"]
>;
