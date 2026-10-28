import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Maximum matching rules one result may publish. */
export const MAX_YARA_MATCHES = 5_000;

/** Maximum matched fields one rule may publish. */
export const MAX_YARA_MATCH_LOCATIONS = 128;

const coverageSchema = z.enum(["complete", "partial"]);

/**
 * Caller intent for YARA-X scanning over a caller-supplied `yr` binary.
 *
 * Generic rule files are always caller-supplied. The crypto-constant tool uses
 * REA's own hash-pinned pack. REA never installs YARA-X, fetches rules, or runs
 * the scanned bytes.
 */
export const scanArtifactWithRulesInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to the local file or directory to scan",
  ),
  rules_path: absoluteLocalPathStringSchema.describe(
    "Absolute path to the caller's YARA rule file or rule directory",
  ),
  max_matches: z
    .int()
    .min(1)
    .max(MAX_YARA_MATCHES)
    .default(1_000)
    .describe("Upper bound on matching rules published"),
});

export const scanForCryptoConstantsInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to the local file or directory to scan",
  ),
  max_matches: z
    .int()
    .min(1)
    .max(MAX_YARA_MATCHES)
    .default(1_000)
    .describe("Upper bound on matching rules published"),
});

export const yaraClientSchema = z.strictObject({
  command: z.string().min(1),
  version: z.string().nullable(),
});

const yaraFieldMatchSchema = z.strictObject({
  identifier: z.string().min(1),
  offset: z.int().nonnegative(),
  length: z.int().nonnegative(),
});

const yaraRuleMatchSchema = z.strictObject({
  rule_id: z.string().min(1),
  namespace: z.string().min(1).nullable(),
  tags: z.array(z.string().min(1)),
  fields: z.array(yaraFieldMatchSchema),
});

/** Structural scan result shared by both YARA-X tools. */
export const yaraScanResultSchema = z.strictObject({
  client: yaraClientSchema,
  path: z.string().min(1),
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable(),
  bytes: z.int().nonnegative().nullable(),
  rules_path: z.string().min(1),
  rules_sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable(),
  rule_pack: z.string().min(1).nullable(),
  rule_pack_version: z.int().nonnegative().nullable(),
  matches: z.array(yaraRuleMatchSchema),
  match_count: z.int().nonnegative(),
  field_match_count: z.int().nonnegative(),
  truncated: z.boolean(),
  unparsed_entries: z.int().nonnegative(),
  coverage: coverageSchema,
});

export type YaraScanResult = z.infer<typeof yaraScanResultSchema>;

/** One validated YARA-X scan request. */
export const yaraScanRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("scan_artifact_with_rules"),
    input: scanArtifactWithRulesInputSchema,
  }),
  z.strictObject({
    operation: z.literal("scan_for_crypto_constants"),
    input: scanForCryptoConstantsInputSchema,
  }),
]);

export type YaraScanRequest = z.output<typeof yaraScanRequestSchema>;
export type YaraScanRequestInput = z.input<typeof yaraScanRequestSchema>;
