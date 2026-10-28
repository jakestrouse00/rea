import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Maximum matched rules one result may publish. */
export const MAX_CAPA_RULES = 5_000;

/** Maximum locations one rule may publish. */
export const MAX_CAPA_RULE_LOCATIONS = 64;

/** Supported capa execution backends. `default` leaves capa's own selection. */
export const CAPA_BACKENDS = [
  "default",
  "vivisect",
  "binja",
  "ghidra",
  "ida",
  "dotnet",
  "pefile",
] as const;

const coverageSchema = z.enum(["complete", "partial"]);

/**
 * Caller intent for capability matching over a caller-supplied
 * [capa](https://github.com/mandiant/capa) CLI.
 *
 * REA never installs capa, downloads rule sets, or executes the target. Only
 * rule identity, scope, and match locations reach Evidence; decoded strings,
 * matched bytes, and the rule source stay out.
 */
export const analyzeBinaryCapabilitiesInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a local executable, library, or .NET assembly to match",
  ),
  backend: z
    .enum(CAPA_BACKENDS)
    .default("default")
    .describe(
      "Optional capa backend override; the default leaves capa's own selection",
    ),
  max_rules: z
    .int()
    .min(1)
    .max(MAX_CAPA_RULES)
    .default(1_000)
    .describe("Upper bound on matched rules published"),
});

export type AnalyzeBinaryCapabilitiesInput = z.input<
  typeof analyzeBinaryCapabilitiesInputSchema
>;

export const capaClientSchema = z.strictObject({
  command: z.string().min(1),
  version: z.string().nullable(),
});

const capaAttackSchema = z.strictObject({
  id: z.string().min(1).nullable(),
  tactic: z.string().min(1).nullable(),
  technique: z.string().min(1).nullable(),
});

const capaMbcSchema = z.strictObject({
  id: z.string().min(1).nullable(),
  objective: z.string().min(1).nullable(),
  behavior: z.string().min(1).nullable(),
});

const capaRuleSchema = z.strictObject({
  id: z.string().min(1),
  namespace: z.string().min(1).nullable(),
  scope: z.string().min(1).nullable(),
  authors: z.array(z.string().min(1)),
  attack: z.array(capaAttackSchema),
  mbc: z.array(capaMbcSchema),
  match_count: z.int().nonnegative(),
  locations: z.array(z.string().min(1)),
});

/** Structural capability-match result returned by the provider adapter. */
export const analyzeBinaryCapabilitiesResultSchema = z.strictObject({
  client: capaClientSchema,
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.int().nonnegative(),
  format: z.string().min(1).nullable(),
  arch: z.string().min(1).nullable(),
  os: z.string().min(1).nullable(),
  rules: z.array(capaRuleSchema),
  rule_count: z.int().nonnegative(),
  match_count: z.int().nonnegative(),
  truncated: z.boolean(),
  unparsed_entries: z.int().nonnegative(),
  coverage: coverageSchema,
});

export type AnalyzeBinaryCapabilitiesResult = z.infer<
  typeof analyzeBinaryCapabilitiesResultSchema
>;

/** One validated capability-matching request. */
export const analyzeBinaryCapabilitiesRequestSchema = z.strictObject({
  operation: z.literal("analyze_binary_capabilities"),
  input: analyzeBinaryCapabilitiesInputSchema,
});

export type AnalyzeBinaryCapabilitiesRequest = z.infer<
  typeof analyzeBinaryCapabilitiesRequestSchema
>;
