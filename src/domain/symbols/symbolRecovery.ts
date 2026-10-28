import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Maximum symbols one result may publish. */
export const MAX_RECOVERED_SYMBOLS = 10_000;

/** Maximum caller-supplied names one demangle request may carry. */
export const MAX_DEMANGLE_NAMES = 256;

const coverageSchema = z.enum(["complete", "partial"]);

const symbolRecoveryClientSchema = z.strictObject({
  command: z.string().min(1),
  version: z.string().min(1).nullable(),
});

/**
 * Caller intent for symbol recovery over caller-supplied GoReSym, rustfilt,
 * and dump_syms binaries. REA never installs or downloads them and never
 * executes the analyzed target.
 */
export const recoverGoSymbolsInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a Go executable, library, or stripped binary",
  ),
  max_functions: z
    .int()
    .min(1)
    .max(MAX_RECOVERED_SYMBOLS)
    .default(5_000)
    .describe("Upper bound on reported functions"),
});

export const demangleRustNameInputSchema = z.strictObject({
  names: z
    .array(z.string().min(1).max(4_096))
    .min(1)
    .max(MAX_DEMANGLE_NAMES)
    .describe("Mangled Rust symbol names to demangle"),
});

export const generateSymbolTableInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a local executable or library",
  ),
  max_functions: z
    .int()
    .min(1)
    .max(MAX_RECOVERED_SYMBOLS)
    .default(10_000)
    .describe("Upper bound on reported functions"),
});

/** Structural Go symbol recovery result. */
export const recoverGoSymbolsResultSchema = z.strictObject({
  client: symbolRecoveryClientSchema,
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.int().nonnegative(),
  go_version: z.string().min(1).nullable(),
  arch: z.string().min(1).nullable(),
  os: z.string().min(1).nullable(),
  module_path: z.string().min(1).nullable(),
  functions: z.array(
    z.strictObject({
      name: z.string().min(1),
      entry: z.string().min(1).nullable(),
      size: z.int().nonnegative().nullable(),
    }),
  ),
  function_count: z.int().nonnegative(),
  truncated: z.boolean(),
  unparsed_entries: z.int().nonnegative(),
  coverage: coverageSchema,
});

/** Structural Rust demangling result. */
export const demangleRustNameResultSchema = z.strictObject({
  client: symbolRecoveryClientSchema,
  names: z.array(
    z.strictObject({
      mangled: z.string().min(1),
      demangled: z.string().min(1).nullable(),
    }),
  ),
  name_count: z.int().nonnegative(),
  demangled_count: z.int().nonnegative(),
  coverage: coverageSchema,
});

/** Structural Breakpad symbol-table result. */
export const generateSymbolTableResultSchema = z.strictObject({
  client: symbolRecoveryClientSchema,
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.int().nonnegative(),
  module: z
    .strictObject({
      os: z.string().min(1).nullable(),
      arch: z.string().min(1).nullable(),
      id: z.string().min(1).nullable(),
      name: z.string().min(1).nullable(),
    })
    .nullable(),
  functions: z.array(
    z.strictObject({
      name: z.string().min(1),
      address: z.string().min(1).nullable(),
      size: z.int().nonnegative().nullable(),
      parameter_size: z.int().nonnegative().nullable(),
    }),
  ),
  function_count: z.int().nonnegative(),
  public_count: z.int().nonnegative(),
  file_count: z.int().nonnegative(),
  truncated: z.boolean(),
  unparsed_entries: z.int().nonnegative(),
  coverage: coverageSchema,
});

export type RecoverGoSymbolsResult = z.infer<
  typeof recoverGoSymbolsResultSchema
>;
export type DemangleRustNameResult = z.infer<
  typeof demangleRustNameResultSchema
>;
export type GenerateSymbolTableResult = z.infer<
  typeof generateSymbolTableResultSchema
>;

/** One validated symbol-recovery request. */
export const symbolRecoveryRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("recover_go_symbols"),
    input: recoverGoSymbolsInputSchema,
  }),
  z.strictObject({
    operation: z.literal("demangle_rust_name"),
    input: demangleRustNameInputSchema,
  }),
  z.strictObject({
    operation: z.literal("generate_symbol_table"),
    input: generateSymbolTableInputSchema,
  }),
]);

export type SymbolRecoveryRequest = z.output<
  typeof symbolRecoveryRequestSchema
>;
export type SymbolRecoveryRequestInput = z.input<
  typeof symbolRecoveryRequestSchema
>;
