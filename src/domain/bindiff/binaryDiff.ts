import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";
import { evidenceInputSchema } from "../evidenceReference.js";
import { digestSchema } from "../digests.js";

/** Maximum matched function pairs one diff may publish. */
export const MAX_BINARY_DIFF_MATCHES = 10_000;

/**
 * Caller intent for a provider-backed binary comparison. Both sides are
 * retained artifact observations; REA never executes either binary.
 */
export const binaryDiffInputSchema = z.strictObject({
  left: evidenceInputSchema,
  right: evidenceInputSchema,
  max_matches: z
    .int()
    .min(1)
    .max(MAX_BINARY_DIFF_MATCHES)
    .default(2_000)
    .describe("Upper bound on matched function pairs published"),
});

export type BinaryDiffInput = z.input<typeof binaryDiffInputSchema>;

const binaryDiffMatchSchema = z.strictObject({
  primary_address: z.string().min(1),
  primary_name: z.string().min(1).nullable(),
  secondary_address: z.string().min(1),
  secondary_name: z.string().min(1).nullable(),
  similarity: z.number().min(0).max(1),
  confidence: z.number().min(0).max(1),
  names_changed: z.boolean(),
});

/** Structural provider-backed binary comparison payload. */
export const binaryDiffResultSchema = z
  .object({
    status: z.enum(["unchanged", "changed", "unknown"]),
    function_match: z.strictObject({
      matched: z.int().nonnegative(),
      unmatched_primary: z.int().nonnegative(),
      unmatched_secondary: z.int().nonnegative(),
    }),
    left_subject_sha256: digestSchema,
    right_subject_sha256: digestSchema,
    summary: z.strictObject({
      matched: z.int().nonnegative(),
      changed: z.int().nonnegative(),
      unresolved: z.int().nonnegative(),
    }),
    matches: z.array(binaryDiffMatchSchema),
    changes: z.array(binaryDiffMatchSchema),
    limitations: z.array(z.string()),
  })
  .superRefine((result, context) => {
    if (result.summary.matched !== result.matches.length)
      context.addIssue({
        code: "custom",
        path: ["summary", "matched"],
        message: "Binary diff summary must count its matched pairs.",
      });
    if (result.summary.changed !== result.changes.length)
      context.addIssue({
        code: "custom",
        path: ["summary", "changed"],
        message: "Binary diff summary must count its changed pairs.",
      });
    const changed = result.changes.every((change) =>
      result.matches.some(
        (match) =>
          match.primary_address === change.primary_address &&
          match.secondary_address === change.secondary_address,
      ),
    );
    if (!changed)
      context.addIssue({
        code: "custom",
        path: ["changes"],
        message: "Binary diff changes must be drawn from its matches.",
      });
  });

export type BinaryDiffResult = z.infer<typeof binaryDiffResultSchema>;

/** One validated BinExport export request. */
export const exportBinexportInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to the local executable or library to export",
  ),
  output_directory: absoluteLocalPathStringSchema.describe(
    "Local directory that receives one new subdirectory with the .BinExport file",
  ),
});

export type ExportBinexportInput = z.input<typeof exportBinexportInputSchema>;

const exportedFileSchema = z.strictObject({
  relative_path: z.string().min(1),
  bytes: z.int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  format: z.enum(["binexport", "unknown"]),
});

/** Structural BinExport export result. */
export const exportBinexportResultSchema = z.strictObject({
  client: z.strictObject({
    command: z.string().min(1),
    version: z.string().min(1).nullable(),
  }),
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.int().nonnegative(),
  output_directory: z.string().min(1),
  file: exportedFileSchema,
  coverage: z.enum(["complete", "partial"]),
});

export type ExportBinexportResult = z.infer<typeof exportBinexportResultSchema>;

/** One validated BinExport export command. */
export const exportBinexportRequestSchema = z.strictObject({
  operation: z.literal("export_binexport_protobuf"),
  input: exportBinexportInputSchema,
});

export type ExportBinexportRequest = z.input<
  typeof exportBinexportRequestSchema
>;
