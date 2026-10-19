import { isAbsolute } from "node:path";
import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

const hexAddressSchema = z.string().regex(/^0x[0-9a-f]+$/u);
const offsetSchema = z.number().int().min(0).max(0xffff_ffff);
const u16Schema = z.number().int().min(0).max(0xffff);
const u32Schema = z.number().int().min(0).max(0xffff_ffff);

/**
 * Caller boundary for execution-free NativeAOT structural inspection. The
 * parser decides paging defaults; the schema preserves the caller's choice.
 */
export const inspectNativeAotTypesInputSchema = z.strictObject({
  path: localPathStringSchema
    .refine(isAbsolute, {
      message:
        "path must be an absolute local filesystem path (for example /tmp/App.exe)",
    })
    .describe(
      "Absolute path to a PE image to inspect for NativeAOT/ReadyToRun structural metadata",
    ),
  offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe(
      "First recovered row to return in this page; omitted or 0 starts at the first row",
    ),
  limit: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe(
      "Maximum recovered rows to return in this page; the parser applies its own bounded default",
    ),
});

export type InspectNativeAotTypesInput = z.infer<
  typeof inspectNativeAotTypesInputSchema
>;

/**
 * One detection observation for the NativeAOT/ReadyToRun surface. Statuses
 * distinguish observed presence, observed absence, and inconclusive bytes;
 * statuses never guess NativeAOT identity from the other signals.
 */
const detectionSignalSchema = z.strictObject({
  signal: z.enum([
    "readytorun-cli-signature",
    "readytorun-header",
    "dotnet-runtime-debug-header-export",
    "managed-section",
  ]),
  status: z.enum(["present", "absent", "uncertain", "not-applicable"]),
  detail: z.string().nullable(),
  file_offset: offsetSchema.nullable(),
  va: hexAddressSchema.nullable(),
});

/**
 * One ReadyToRun directory row. NativeAOT entries record virtual start and
 * end ranges; CoreCLR entries record an RVA and byte size. Unmapped or
 * version-divergent values stay null with a limitation string.
 */
const readytorunSectionSchema = z.strictObject({
  type: u32Schema,
  type_name: z.string().nullable(),
  flags: u32Schema.nullable(),
  start_va: hexAddressSchema.nullable(),
  end_va: hexAddressSchema.nullable(),
  start_file_offset: offsetSchema.nullable(),
  end_file_offset: offsetSchema.nullable(),
});

const readytorunHeaderSchema = z.strictObject({
  file_offset: offsetSchema,
  va: hexAddressSchema.nullable(),
  signature: z.literal("0x00525452"),
  major_version: u16Schema,
  minor_version: u16Schema,
  flags: u32Schema,
  section_count: u16Schema,
  entry_size: z.number().int().min(0).max(0xff),
  entry_type: z.number().int().min(0).max(0xff),
  entry_layout: z.enum(["nativeaot-module", "coreclr-readytorun"]),
  format_hint: z.string().nullable(),
  sections: z.array(readytorunSectionSchema),
});

/** One recovered MethodTable-shaped structure with its exact file and VA identity. */
const methodTableRowSchema = z.strictObject({
  kind: z.literal("method-table"),
  index: z.number().int().min(0),
  file_offset: offsetSchema,
  end_file_offset: offsetSchema.nullable(),
  va: hexAddressSchema.nullable(),
  flags: u32Schema,
  element_type: z.enum(["class", "value-type"]),
  base_size: u32Schema,
  related_type: hexAddressSchema.nullable(),
  related_type_file_offset: offsetSchema.nullable(),
  vtable_slot_count: u16Schema,
  interface_count: u16Schema,
});

/** One frozen string object matched against the documented String layout. */
const frozenStringRowSchema = z.strictObject({
  kind: z.literal("frozen-string"),
  index: z.number().int().min(0),
  file_offset: offsetSchema,
  va: hexAddressSchema.nullable(),
  char_length: z.number().int().min(0),
  value: z.string().nullable(),
  data_file_offset: offsetSchema,
});

const rowSchema = z.discriminatedUnion("kind", [
  methodTableRowSchema,
  frozenStringRowSchema,
]);

const pagingSchema = z.strictObject({
  offset: z.number().int().min(0),
  limit: z.number().int().min(1),
  total_rows: z.number().int().min(0),
  returned_rows: z.number().int().min(0),
  complete: z
    .boolean()
    .describe(
      "True only when this page ends the admitted rows AND coverage reported no truncation; coverage truncation (for example recovered rows beyond the row budget) keeps this false so omitted rows are never reported as completion",
    ),
});

const coverageSchema = z.strictObject({
  sentinel_scan_bytes_examined: z.number().int().min(0),
  sentinel_scan_bytes_omitted: z.number().int().min(0),
  sentinel_candidates: z.number().int().min(0),
  validated_readytorun_candidates: z.number().int().min(0),
  pointer_slots_examined: z.number().int().min(0),
  pointer_scan_bytes_omitted: z.number().int().min(0),
  method_tables_recovered: z.number().int().min(0),
  frozen_strings_recovered: z.number().int().min(0),
  rows_omitted: z.number().int().min(0),
  truncated: z.boolean(),
});

/** Complete caller result for one NativeAOT artifact inspection page. */
export const nativeAotArtifactInspectionSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string(),
    sha256: digestSchema,
    byte_length: z.number().int().min(0),
    format: z.literal("pe"),
  }),
  pe: z
    .strictObject({
      machine: u16Schema,
      machine_hex: z.string().regex(/^0x[0-9a-f]{4}$/u),
      architecture: z.enum(["x86", "x86_64", "arm", "arm64"]),
      image_base: hexAddressSchema,
      pointer_size: z.union([z.literal(4), z.literal(8)]),
    })
    .nullable(),
  status: z.enum(["complete", "partial", "not-applicable"]),
  reason: z.string().nullable(),
  detection: z.array(detectionSignalSchema),
  readytorun_header: readytorunHeaderSchema.nullable(),
  rows: z.array(rowSchema),
  paging: pagingSchema,
  coverage: coverageSchema,
  limitations: z.array(z.string()),
});

export type NativeAotArtifactInspection = z.infer<
  typeof nativeAotArtifactInspectionSchema
>;
export type NativeAotInspectionRow = z.infer<typeof rowSchema>;
export type NativeAotDetectionSignal = z.infer<typeof detectionSignalSchema>;
