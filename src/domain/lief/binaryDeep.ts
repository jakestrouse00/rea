import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";
import {
  liefArtifactSchema,
  liefFormatSchema,
  pdbReferenceSchema,
} from "./liefArtifact.js";
import { liefBridgeAdvertisementSchema } from "./liefBridgeFrames.js";

/** Input: one explicitly selected local binary. */
export const inspectBinaryDeepInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the selected ELF, PE or Mach-O file",
  ),
});

/** One architecture row; fat slices carry their own file span, thin ones null. */
const architectureSchema = z.strictObject({
  index: z.number().int().nonnegative(),
  cpu: z.string().min(1),
  bits: z.number().int().positive().nullable(),
  little_endian: z.boolean().nullable(),
  entrypoint: z.number().int().nonnegative().nullable(),
  image_base: z.number().int().nonnegative().nullable(),
  /** File span of one fat slice; null for a thin binary. */
  size: z.number().int().nonnegative().nullable(),
  offset: z.number().int().nonnegative().nullable(),
});

/** One dynamic-table entry with LIEF's tag name and the recorded value. */
const dynamicEntrySchema = z.strictObject({
  tag: z.string().min(1),
  value: z.number().int().nonnegative(),
});

/** ELF facts the section/segment and export lanes do not own. */
const elfDynamicSchema = z.strictObject({
  interpreter: z.string().min(1).nullable(),
  soname: z.string().min(1).nullable(),
  needed: z.array(z.string().min(1)),
  rpath: z.array(z.string()),
  runpath: z.array(z.string()),
  entries: z.array(dynamicEntrySchema),
});

/** One linked Mach-O dylib with its recorded version pair. */
const machoLibrarySchema = z.strictObject({
  name: z.string().min(1),
  current_version: z.string().min(1).nullable(),
  compatibility_version: z.string().min(1).nullable(),
});

/** One load command: kind and size, with a segment name where the kind has one. */
const machoLoadCommandSchema = z.strictObject({
  kind: z.string().min(1),
  size: z.number().int().nonnegative(),
  segment_name: z.string().min(1).nullable(),
});

const machoStructureSchema = z.strictObject({
  uuid: z.string().min(1).nullable(),
  fat: z.boolean(),
  libraries: z.array(machoLibrarySchema),
  load_commands: z.array(machoLoadCommandSchema),
});

/** One PE data directory row; REA records the declaration, not its contents. */
const peDataDirectorySchema = z.strictObject({
  name: z.string().min(1),
  rva: z.number().int().nonnegative(),
  size: z.number().int().nonnegative(),
});

const peDebugEntrySchema = z.strictObject({
  kind: z.string().min(1),
  pdb_reference: pdbReferenceSchema.nullable(),
});

const peStructureSchema = z.strictObject({
  machine: z.string().min(1).nullable(),
  subsystem: z.string().min(1).nullable(),
  characteristics: z.array(z.string().min(1)),
  data_directories: z.array(peDataDirectorySchema),
  debug_entries: z.array(peDebugEntrySchema),
});

/** Counts only: the owning tools report the per-entry layout. */
const structureSummarySchema = z.strictObject({
  section_count: z.number().int().nonnegative(),
  segment_count: z.number().int().nonnegative(),
  linked_library_count: z.number().int().nonnegative(),
});

const debugSectionSchema = z.strictObject({
  name: z.string().min(1),
  size: z.number().int().nonnegative(),
});

const debugSourcesSchema = z.strictObject({
  dwarf: z.strictObject({
    present: z.boolean(),
    sections: z.array(debugSectionSchema),
  }),
  pdb_reference: pdbReferenceSchema.nullable(),
});

/** A fact this lane deliberately leaves to the tool that owns it. */
const delegatedFactSchema = z.strictObject({
  fact: z.string().min(1),
  tool: z.string().min(1),
});

const truncationSchema = z.strictObject({
  architectures: z.boolean(),
  dynamic_entries: z.boolean(),
  libraries: z.boolean(),
  load_commands: z.boolean(),
  data_directories: z.boolean(),
  debug_entries: z.boolean(),
  debug_sections: z.boolean(),
});

/** Complete bounded observation of one binary's LIEF-unique structure. */
export const binaryDeepReportSchema = z
  .strictObject({
    artifact: liefArtifactSchema,
    bridge: liefBridgeAdvertisementSchema,
    format: liefFormatSchema,
    architectures: z.array(architectureSchema),
    structure_summary: structureSummarySchema,
    dynamic: elfDynamicSchema.nullable(),
    macho: machoStructureSchema.nullable(),
    pe: peStructureSchema.nullable(),
    debug_sources: debugSourcesSchema,
    delegated_facts: z.array(delegatedFactSchema),
    truncated: truncationSchema,
    complete: z.boolean(),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    if (report.format === "elf" && report.dynamic === null)
      context.addIssue({
        code: "custom",
        path: ["dynamic"],
        message: "An ELF report carries its dynamic-table facts.",
      });
    if (
      (report.format === "pe") !== (report.pe !== null) ||
      (report.format === "macho") !== (report.macho !== null) ||
      (report.format === "macho-fat") !== (report.macho !== null)
    )
      context.addIssue({
        code: "custom",
        path: ["format"],
        message: "Format-specific structure must match the classified format.",
      });
    const truncated = Object.values(report.truncated).some(
      (value) => value === true,
    );
    if (report.complete === truncated)
      context.addIssue({
        code: "custom",
        path: ["complete"],
        message: "completeness is the exact negation of any truncation",
      });
  });

export type BinaryDeepReport = z.infer<typeof binaryDeepReportSchema>;
