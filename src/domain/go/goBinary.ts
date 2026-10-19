import { z } from "zod";
import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";
import { CANONICAL_BASE64_PATTERN } from "../stringPatterns.js";

const sourceRangeSchema = z.strictObject({
  offset: z.number().int().nonnegative(),
  bytes: z.number().int().nonnegative(),
});
const moduleIdentitySchema = z.strictObject({
  path: z.string(),
  version: z.string(),
  sum: z.string().nullable(),
});

/** Module identities retain development versions, local replacements and missing sums verbatim. */
export const goModuleSchema = moduleIdentitySchema.extend({
  replacement: moduleIdentitySchema.nullable(),
});

/** Parsed records alongside unrecognized text lines and exact non-UTF-8 line bytes. */
export const goModuleMetadataSchema = z.strictObject({
  path: z.string().nullable(),
  main: goModuleSchema.nullable(),
  dependencies: z.array(goModuleSchema),
  settings: z.array(z.strictObject({ key: z.string(), value: z.string() })),
  unparsed_lines: z.array(z.string()),
  unparsed_line_bytes_base64: z.array(
    z.string().regex(CANONICAL_BASE64_PATTERN),
  ),
  complete: z.boolean(),
});

/** One exact local artifact, independent of any active disassembler target. */
export const inspectGoBinaryInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the selected executable or library",
  ),
});

/** Compiler-written build information and its original file-backed source ranges. */
export const goBuildInfoSchema = z.strictObject({
  header_offset: z.number().int().nonnegative(),
  encoding: z.enum(["inline", "pointer"]),
  go_version: z.string().nullable(),
  go_version_bytes_base64: z.string().regex(CANONICAL_BASE64_PATTERN),
  module_text: z.string().nullable(),
  module_bytes_base64: z.string().regex(CANONICAL_BASE64_PATTERN),
  version_location: sourceRangeSchema,
  module_location: sourceRangeSchema,
  module: goModuleMetadataSchema,
});

/** Complete bounded build-metadata observation; absence does not identify a binary as non-Go. */
export const goBinarySchema = z
  .strictObject({
    artifact: z.strictObject({
      path: localPathStringSchema,
      sha256: digestSchema,
      bytes: z.number().int().nonnegative(),
    }),
    format: z.enum(["elf", "pe", "macho"]),
    architecture: z.string(),
    bits: z.union([z.literal(32), z.literal(64)]),
    byte_order: z.enum(["little", "big"]),
    build_info: goBuildInfoSchema.nullable(),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    const info = report.build_info;
    if (info === null) return;
    if (info.header_offset > report.artifact.bytes - 32)
      context.addIssue({
        code: "custom",
        path: ["build_info", "header_offset"],
        message: "Build-info header is outside the selected artifact.",
      });
    for (const field of ["version_location", "module_location"] as const) {
      const range = info[field];
      if (
        range.offset > report.artifact.bytes ||
        range.bytes > report.artifact.bytes - range.offset
      )
        context.addIssue({
          code: "custom",
          path: ["build_info", field],
          message: "Build-info source range is outside the selected artifact.",
        });
    }
    for (const [field, range, description] of [
      ["go_version_bytes_base64", info.version_location, "compiler"],
      ["module_bytes_base64", info.module_location, "module"],
    ] as const) {
      const encoded = info[field];
      const padding = encoded.endsWith("==")
        ? 2
        : encoded.endsWith("=")
          ? 1
          : 0;
      if ((encoded.length / 4) * 3 - padding !== range.bytes)
        context.addIssue({
          code: "custom",
          path: ["build_info", field],
          message: `Encoded ${description} bytes do not match their reported source length.`,
        });
    }
  });

export type GoModule = z.infer<typeof goModuleSchema>;
export type GoModuleMetadata = z.infer<typeof goModuleMetadataSchema>;
export type GoBinary = z.infer<typeof goBinarySchema>;
export type InspectGoBinaryInput = z.infer<typeof inspectGoBinaryInputSchema>;

const hexAddress = z
  .string()
  .regex(/^0x[0-9a-f]+$/u)
  .describe("Lowercase hexadecimal virtual address with a 0x prefix");

/** Caller-controlled page bounds for the embedded Go procedure table. */
export const inspectGoProcedureTableInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the selected executable or library",
  ),
  offset: z
    .number()
    .int()
    .min(0)
    .default(0)
    .describe("Zero-based procedure-table row index where the page starts"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(500)
    .default(50)
    .describe("Maximum procedures returned in one page"),
});

/** One decoded pclntab functab row with unknown values preserved as null. */
export const goProcedureEntrySchema = z.strictObject({
  index: z.number().int().min(0),
  name: z
    .string()
    .nullable()
    .describe(
      "Resolved funcnametab bytes; null for linker holes, out-of-range name offsets and non-UTF-8 names",
    ),
  entry_offset: z
    .number()
    .int()
    .min(0)
    .nullable()
    .describe(
      "Entry position relative to the recovered text base, as produced",
    ),
  end_offset: z
    .number()
    .int()
    .min(0)
    .nullable()
    .describe(
      "Next-entry or table-sentinel position relative to the text base",
    ),
  entry_address: hexAddress.nullable(),
  end_address: hexAddress
    .nullable()
    .describe(
      "Exclusive end position from the next entry or the table sentinel; null when the text base could not be recovered",
    ),
});

/** Validated pclntab header facts, without decoding any procedure rows. */
export const goPclntabSchema = z.strictObject({
  location: z.strictObject({
    source: z.enum(["section", "search"]),
    section_name: z.string().nullable(),
    file_offset: z.number().int().min(0),
    address: hexAddress,
    bytes: z.number().int().min(1),
  }),
  magic: z
    .string()
    .regex(/^0x[0-9a-f]{8}$/u)
    .describe("Raw observed 4-byte pclntab magic word"),
  era: z.enum(["go1.2-1.15", "go1.16-1.17", "go1.18-1.19", "go1.20+"]),
  min_lc: z.number().int().min(1).max(4),
  ptr_size: z.union([z.literal(4), z.literal(8)]),
  nfunc: z.number().int().min(0).nullable(),
  nfiles: z.number().int().min(0).nullable(),
  funcname_bytes: z.number().int().min(0).nullable(),
  functab: z
    .strictObject({
      file_offset: z.number().int().min(0),
      entry_width: z.number().int().min(1),
      count: z.number().int().min(1),
    })
    .nullable(),
  text_start: hexAddress
    .nullable()
    .describe(
      "Raw pclntab-header textStart value; go1.16-1.17 eras have none and go1.26+ zero it",
    ),
  text_base: z
    .strictObject({
      address: hexAddress,
      source: z.enum(["pclntab-header", "moduledata", "first-entry"]),
    })
    .nullable(),
  moduledata: z.strictObject({
    found: z.boolean(),
    file_offset: z.number().int().min(0).nullable(),
    nfunc_matches: z.boolean().nullable(),
    text_address: hexAddress.nullable(),
  }),
  legacy: z
    .boolean()
    .describe(
      "True when the function table was recognized but left undecoded; procedures remain unknown",
    ),
});

/** Complete bounded procedure-table page; absence does not identify a binary as non-Go. */
export const goProcedureTableSchema = z
  .strictObject({
    artifact: z.strictObject({
      path: localPathStringSchema,
      sha256: digestSchema,
      bytes: z.number().int().nonnegative(),
    }),
    format: z.enum(["elf", "pe", "macho"]),
    architecture: z.string(),
    bits: z.union([z.literal(32), z.literal(64)]),
    byte_order: z.enum(["little", "big"]),
    pclntab: goPclntabSchema.nullable(),
    offset: z.number().int().min(0),
    limit: z.number().int().min(1).max(500),
    total: z.number().int().min(0),
    procedures: z.array(goProcedureEntrySchema).max(500),
    next_offset: z.number().int().min(0).nullable(),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    if (
      report.procedures.some(
        (procedure, position) => procedure.index !== report.offset + position,
      )
    )
      context.addIssue({
        code: "custom",
        path: ["procedures"],
        message:
          "Procedure rows must carry contiguous table indexes starting at the offset.",
      });
    const next = report.offset + report.procedures.length;
    const expectedNext = next < report.total ? next : null;
    if (report.next_offset !== expectedNext)
      context.addIssue({
        code: "custom",
        path: ["next_offset"],
        message:
          "Paging continuation must match the decoded row window and total.",
      });
    if (report.pclntab === null && report.total !== 0)
      context.addIssue({
        code: "custom",
        path: ["total"],
        message: "Total must be zero when no procedure table was recovered.",
      });
    if (
      report.pclntab !== null &&
      report.pclntab.nfunc !== null &&
      report.total !== report.pclntab.nfunc
    )
      context.addIssue({
        code: "custom",
        path: ["total"],
        message:
          "Total must match the decoded function count of the recovered table.",
      });
  });

export type GoProcedureEntry = z.infer<typeof goProcedureEntrySchema>;
export type GoPclntab = z.infer<typeof goPclntabSchema>;
export type GoProcedureTable = z.infer<typeof goProcedureTableSchema>;
export type InspectGoProcedureTableInput = z.infer<
  typeof inspectGoProcedureTableInputSchema
>;
