import { z } from "zod";

/**
 * Unsigned 64-bit values as exact decimal strings. The minidump layout stores
 * 64-bit addresses and sizes that exceed JSON number precision, so every
 * contract surface carries the source value verbatim instead of a projection.
 */
export const u64Schema = z
  .string()
  .regex(/^[0-9]+$/u, "Expected an unsigned decimal string")
  .describe("Unsigned 64-bit value written as an exact decimal string");

/** Unsigned 32-bit values fit plain JSON numbers without precision loss. */
export const u32Schema = z
  .number()
  .int()
  .min(0)
  .max(0xffffffff)
  .describe("Unsigned 32-bit value");
