import { z } from "zod";

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
      /^\/dev\/(cu|tty)\.[^\x2f]+$/u,
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
