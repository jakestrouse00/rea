import { z } from "zod";
import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

/** Absolute filesystem path and stable identity of one selected .wer file. */
export const inspectWerReportInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the selected Windows Error Reporting report",
  ),
});

/** One exact key/value line as the file wrote it; values are never interpreted. */
export const werFieldSchema = z.strictObject({
  key: z.string(),
  value: z.string(),
});

/** Grouped `Sig[N]` or `DynamicSig[N]` module-signature entries, in file order. */
export const werSignatureSchema = z.strictObject({
  group: z.enum(["sig", "dynamic-sig"]),
  index: z.number().int().nonnegative(),
  fields: z.array(werFieldSchema),
});

/**
 * Complete bounded text observation of a WER report. Every field is preserved
 * verbatim (including paths, usernames and version strings); REA applies no
 * secrecy inference and no value rewriting, because redaction decisions belong
 * to the caller's own policy.
 */
export const werReportSchema = z.strictObject({
  artifact: z.strictObject({
    path: localPathStringSchema,
    sha256: digestSchema,
    bytes: z.number().int().nonnegative(),
  }),
  encoding: z.enum(["utf-16le", "utf-8", "ascii"]),
  had_byte_order_mark: z.boolean(),
  line_count: z.number().int().nonnegative(),
  fields: z.array(werFieldSchema),
  signatures: z.array(werSignatureSchema),
  /** Lines without any `=` separator are preserved as recorded text. */
  unparsed_lines: z.array(z.string()),
  complete: z.boolean(),
  limitations: z.array(z.string()),
});

export type WerField = z.infer<typeof werFieldSchema>;
export type WerSignature = z.infer<typeof werSignatureSchema>;
export type WerReport = z.infer<typeof werReportSchema>;
export type InspectWerReportInput = z.infer<typeof inspectWerReportInputSchema>;
