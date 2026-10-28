import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  EMU_ARCHITECTURES,
  EMU_LIMITS,
  EMU_PROTOCOL_VERSION,
} from "./emuLimits.js";

export const emuArchitectureSchema = z.enum(EMU_ARCHITECTURES);
export const emuEndiannessSchema = z.enum(["little", "big"]);

const hexAddressSchema = z.string().regex(/^0x[0-9a-f]{1,16}$/u);
const hexValueSchema = z
  .string()
  .regex(/^0x[0-9a-f]{1,32}$/u)
  .describe("Unsigned hexadecimal value, including the 0x prefix");
const hexBytesSchema = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const digestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const registerNameSchema = z.string().regex(/^[a-z][a-z0-9]{1,15}$/u);

/** Caller-selected source of the code bytes one job emulates. */
export const emuCodeSourceSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("file"),
    path: absoluteLocalPathStringSchema.describe(
      "Absolute path to the local artifact holding the code",
    ),
    offset: z
      .int()
      .min(0)
      .default(0)
      .describe("File offset of the first emulated code byte"),
    length: z
      .int()
      .min(1)
      .max(EMU_LIMITS.maxCodeBytes)
      .describe("Number of code bytes admitted from the file"),
  }),
  z.strictObject({
    kind: z.literal("hex"),
    hex: hexBytesSchema.describe(
      "Caller-supplied instruction bytes as an even-length hexadecimal string",
    ),
  }),
]);

/** Caller intent for one isolated, bounded emulation of a code slice. */
export const emulateFunctionInputSchema = z.strictObject({
  arch: emuArchitectureSchema.describe(
    "Instruction set REA asks Unicorn to decode and Keystone to encode",
  ),
  endianness: emuEndiannessSchema
    .default("little")
    .describe(
      "Byte order inside the emulated memory; only big-endian-capable architectures accept big",
    ),
  source: emuCodeSourceSchema,
  code_base: hexAddressSchema
    .default(EMU_LIMITS.defaultCodeBase)
    .describe("Emulated address of the first code byte"),
  entry_offset: z
    .int()
    .min(0)
    .default(0)
    .describe("Entry address as an offset from code_base"),
  stack_size: z
    .int()
    .min(0x1000)
    .max(EMU_LIMITS.maxStackSize)
    .default(EMU_LIMITS.defaultStackSize)
    .describe("Bytes of the private stack region mapped for the job"),
  args: z
    .array(hexValueSchema)
    .max(EMU_LIMITS.maxArguments)
    .default([])
    .describe(
      "Stub argument values placed by the architecture calling convention",
    ),
  max_steps: z
    .int()
    .min(1)
    .max(EMU_LIMITS.maxSteps)
    .default(EMU_LIMITS.defaultSteps)
    .describe("Upper bound on executed instructions"),
  timeout_ms: z
    .int()
    .min(1)
    .max(EMU_LIMITS.maxTimeoutMs)
    .default(EMU_LIMITS.defaultTimeoutMs)
    .describe("Upper bound on emulated wall time"),
  stop_addresses: z
    .array(hexAddressSchema)
    .max(EMU_LIMITS.maxStopAddresses)
    .default([])
    .describe(
      "Addresses that end the job when reached, such as a caller-declared callee entry",
    ),
  observe_registers: z
    .array(registerNameSchema)
    .max(EMU_LIMITS.maxRegisters)
    .default([])
    .describe("Registers reported as typed values when the job ends"),
  observe_memory: z
    .array(
      z.strictObject({
        address: hexAddressSchema,
        length: z.int().min(1).max(EMU_LIMITS.maxMemoryObservationBytes),
      }),
    )
    .max(EMU_LIMITS.maxMemoryObservations)
    .default([])
    .describe(
      "Emulated memory windows reported as length and SHA-256, never as bytes",
    ),
});

/** Caller intent for one Keystone assembly job used in patch crafting. */
export const assembleBytesInputSchema = z.strictObject({
  arch: emuArchitectureSchema.describe(
    "Instruction set REA asks Keystone to encode",
  ),
  endianness: emuEndiannessSchema
    .default("little")
    .describe("Byte order of the encoded instructions"),
  base_address: hexAddressSchema
    .default("0x0")
    .describe("Address Keystone assembles relative to"),
  assembly: z
    .string()
    .min(1)
    .max(EMU_LIMITS.maxAssemblyTextBytes)
    .describe("Assembly source text to encode"),
});

export const emuBridgeIdentitySchema = z.strictObject({
  protocol: z.literal(EMU_PROTOCOL_VERSION),
  unicorn_version: z.string().min(1).nullable(),
  keystone_version: z.string().min(1).nullable(),
});

export const EMU_EXIT_REASONS = [
  "returned",
  "stop_address",
  "max_steps",
  "timeout",
  "invalid_memory_access",
  "unsupported_instruction",
  "bridge_error",
] as const;

const emuRegisterValueSchema = z.strictObject({
  name: registerNameSchema,
  value: hexValueSchema,
});

const emuMemoryValueSchema = z.strictObject({
  address: hexAddressSchema,
  length: z.int().min(1),
  sha256: digestSchema,
});

const emuCallTargetSchema = z.strictObject({
  address: hexAddressSchema,
  count: z.int().min(1),
});

/** Structural result of one bounded emulation: values, hashes, and edge ids. */
export const emulateFunctionResultSchema = z.strictObject({
  bridge: emuBridgeIdentitySchema,
  arch: emuArchitectureSchema,
  endianness: emuEndiannessSchema,
  code: z.strictObject({
    source: z.enum(["file", "hex"]),
    path: z.string().min(1).nullable(),
    offset: z.int().min(0).nullable(),
    length: z.int().min(1),
    sha256: digestSchema,
  }),
  code_base: hexAddressSchema,
  entry: hexAddressSchema,
  exit: z.enum(EMU_EXIT_REASONS),
  exit_detail: z.strictObject({
    code: z.string().regex(/^[a-z0-9_]{1,64}$/u),
    address: hexAddressSchema.nullable(),
  }),
  executed_steps: z.int().min(0),
  call_count: z.int().min(0),
  call_targets: z.array(emuCallTargetSchema),
  call_targets_truncated: z.boolean(),
  edges: z.array(z.string().regex(/^0x[0-9a-f]{1,16}->0x[0-9a-f]{1,16}$/u)),
  edge_count: z.int().min(0),
  edges_truncated: z.boolean(),
  registers: z.array(emuRegisterValueSchema),
  unknown_registers: z.array(registerNameSchema),
  memory: z.array(emuMemoryValueSchema),
  memory_omitted: z.int().min(0),
  coverage: z.enum(["complete", "partial"]),
});

export type EmulateFunctionResult = z.infer<typeof emulateFunctionResultSchema>;

/** Structural result of one Keystone assembly job. */
export const assembleBytesResultSchema = z.strictObject({
  bridge: emuBridgeIdentitySchema,
  arch: emuArchitectureSchema,
  endianness: emuEndiannessSchema,
  base_address: hexAddressSchema,
  assembly: z.string().min(1),
  bytes_hex: hexBytesSchema,
  size: z.int().min(1),
  sha256: digestSchema,
  instruction_count: z.int().min(1).nullable(),
});

export type AssembleBytesResult = z.infer<typeof assembleBytesResultSchema>;

/** One validated emulation-lane request. */
export const emuRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("emulate_function_isolated"),
    input: emulateFunctionInputSchema,
  }),
  z.strictObject({
    operation: z.literal("assemble_bytes"),
    input: assembleBytesInputSchema,
  }),
]);

export type EmuRequest = z.output<typeof emuRequestSchema>;
export type EmuRequestInput = z.input<typeof emuRequestSchema>;
