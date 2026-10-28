import { z } from "zod";

import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

const countSchema = z.int().nonnegative();

/**
 * Fixed View8 operation deadline. The provider applies it to every run and
 * analysis settings reports it as a fixed constraint, so the value lives in
 * this pure layer instead of the provider module that both owners cannot share.
 */
export const DEFAULT_VIEW8_OPERATION_TIMEOUT_MS = 300_000;

/** Bounded capture budget for one disassembly stream. */
export const VIEW8_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

/** Bounded admission for one selected bytecode artifact. */
export const VIEW8_MAX_INPUT_BYTES = 64 * 1024 * 1024;
const wordSchema = z.int().nonnegative().max(0xffff_ffff);

/**
 * Caller intent for disassembling one V8 cached-data artifact through a
 * caller-supplied View8 build. Disassembly text stays out of Evidence: only the
 * container header, digest, and bounded line/byte counts are reported.
 */
export const decompileV8BytecodeInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a local V8 cached-data file, such as a bytenode .jsc",
  ),
});

export type DecompileV8BytecodeInput = z.input<
  typeof decompileV8BytecodeInputSchema
>;

export const view8ClientSchema = z.strictObject({
  command: z.string().min(1),
  version: z.string().min(1).nullable(),
});

/**
 * Structural cached-data header facts; the payload is never interpreted.
 *
 * Interpreted words are present only when exactly one pinned layout declares
 * the observed payload size. `layout_unverifiable` keeps every word
 * uninterpreted rather than forcing a foreign header into a pinned map.
 */
export const v8BytecodeContainerSchema = z.strictObject({
  state: z.enum(["recognized", "layout_unverifiable", "unrecognized"]),
  layout: z
    .enum(["v8-code-cache-32-byte-header", "v8-code-cache-24-byte-header"])
    .nullable(),
  magic: z.enum(["v8-cached-data", "unknown"]),
  magic_hex: z.string().regex(/^[0-9a-f]{8}$/u),
  header_bytes: countSchema.nullable(),
  prefix_words: z.array(wordSchema).max(8),
  version_hash: wordSchema.nullable(),
  flag_hash: wordSchema.nullable(),
  source_length: countSchema.nullable(),
  source_hash: wordSchema.nullable(),
  snapshot_checksum: wordSchema.nullable(),
  payload_checksum: wordSchema.nullable(),
  declared_payload_bytes: countSchema.nullable(),
  observed_payload_bytes: countSchema.nullable(),
});

/** Bounded disassembly observation without any recovered text. */
export const v8DisassemblySchema = z.strictObject({
  bytes: countSchema,
  sha256: digestSchema,
  lines: countSchema,
  empty: z.boolean(),
});

export const decompileV8BytecodeResultSchema = z.strictObject({
  client: view8ClientSchema,
  path: z.string().min(1),
  sha256: digestSchema,
  bytes: countSchema,
  container: v8BytecodeContainerSchema,
  disassembly: v8DisassemblySchema,
  coverage: z.enum(["complete", "partial"]),
});

export type DecompileV8BytecodeResult = z.infer<
  typeof decompileV8BytecodeResultSchema
>;

/** One validated V8 bytecode decompilation request. */
export const v8BytecodeRequestSchema = z.strictObject({
  operation: z.literal("decompile_v8_bytecode"),
  input: decompileV8BytecodeInputSchema,
});

export type V8BytecodeRequest = z.input<typeof v8BytecodeRequestSchema>;
