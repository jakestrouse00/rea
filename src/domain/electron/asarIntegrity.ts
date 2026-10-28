import { z } from "zod";

import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Default aggregate bytes checked against header-declared member checksums. */
export const DEFAULT_ASAR_VERIFY_BYTES = 64 * 1024 * 1024;

/** Largest aggregate verification budget this release admits. */
export const MAXIMUM_ASAR_VERIFY_BYTES = 1024 * 1024 * 1024;

/** Default number of V8 bytecode candidates one result may list. */
export const DEFAULT_ASAR_MAX_CANDIDATES = 200;

/** Largest candidate list this release admits. */
export const MAXIMUM_ASAR_MAX_CANDIDATES = 2_000;

const countSchema = z.int().nonnegative();

/**
 * Caller intent for checking one ASAR archive's header-declared member
 * checksums over its packed content and for listing V8 bytecode candidates.
 */
export const inspectAsarIntegrityInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a local Electron ASAR archive",
  ),
  max_verify_bytes: z
    .int()
    .min(0)
    .max(MAXIMUM_ASAR_VERIFY_BYTES)
    .default(DEFAULT_ASAR_VERIFY_BYTES)
    .describe("Aggregate bytes read to check header-declared member checksums"),
  max_candidates: z
    .int()
    .min(1)
    .max(MAXIMUM_ASAR_MAX_CANDIDATES)
    .default(DEFAULT_ASAR_MAX_CANDIDATES)
    .describe("Upper bound on listed V8 bytecode candidates"),
});

export type InspectAsarIntegrityInput = z.input<
  typeof inspectAsarIntegrityInputSchema
>;

/** One validated ASAR integrity request with defaults applied. */
export type InspectAsarIntegrityRequest = z.output<
  typeof inspectAsarIntegrityInputSchema
>;

const containerSchema = z.strictObject({
  header_bytes: countSchema,
  files: countSchema,
  directories: countSchema,
  symlinks: countSchema,
  unpacked_files: countSchema,
});

const memberIntegrityStateSchema = z.enum([
  "verified",
  "mismatched",
  "not_declared",
  "unverified",
]);

const integritySchema = z.strictObject({
  algorithm: z.literal("SHA256").nullable(),
  block_size: countSchema.nullable(),
  members_declaring: countSchema,
  members_verified: countSchema,
  members_mismatched: countSchema,
  members_without_checksums: countSchema,
  members_unverified: countSchema,
  mismatched_paths: z.array(z.string().min(1)),
  verified_bytes: countSchema,
  truncated: z.boolean(),
  state: z.enum(["verified", "mismatched", "partial", "not_declared"]),
});

/** Structural facts only: no member bytes, checksums of payloads, or paths beyond the inventory. */
export const asarIntegrityReportSchema = z.strictObject({
  path: z.string().min(1),
  resolved_path: z.string().min(1),
  sha256: digestSchema,
  bytes: countSchema,
  container: containerSchema,
  integrity: integritySchema,
  handoff: z.strictObject({
    tool: z.literal("decompile_v8_bytecode"),
    command_environment: z.literal("REA_VIEW8_COMMAND"),
    instruction: z.string().min(1),
    candidates: z.array(
      z.strictObject({
        path: z.string().min(1),
        bytes: countSchema,
        sha256: digestSchema.nullable(),
        unpacked: z.boolean(),
        integrity: memberIntegrityStateSchema,
      }),
    ),
  }),
  coverage: z.enum(["complete", "partial"]),
  limitations: z.array(z.string().min(1)),
});

export type AsarIntegrityReport = z.infer<typeof asarIntegrityReportSchema>;
