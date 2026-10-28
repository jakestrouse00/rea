import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";
import {
  liefArtifactSchema,
  liefFormatSchema,
  pdbReferenceSchema,
} from "./liefArtifact.js";
import { liefBridgeAdvertisementSchema } from "./liefBridgeFrames.js";
import { LIEF_LIMITS } from "./liefLimits.js";

/** One bounded debug-info lookup; identity values stay exactly as asked. */
export const liefLookupQuerySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("symbol"),
    name: z.string().min(1).describe("Exact symbol, public or linkage name"),
  }),
  z.strictObject({
    kind: z.literal("address"),
    address: z
      .number()
      .int()
      .nonnegative()
      .describe("Linked virtual address to attribute to a function"),
  }),
]);

export type LiefLookupQuery = z.infer<typeof liefLookupQuerySchema>;

/** Input: one selected artifact plus optional bounded lookups. */
export const extractPdbDwarfInfoInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the selected PDB, ELF, PE or Mach-O file",
  ),
  queries: z
    .array(liefLookupQuerySchema)
    .min(1)
    .max(LIEF_LIMITS.maxQueries)
    .optional()
    .describe(
      `At most ${String(LIEF_LIMITS.maxQueries)} lookups; omit to report only the debug-info inventory`,
    ),
});

/** One debug-info match with every fact it could not establish left null. */
const liefMatchSchema = z.strictObject({
  kind: z.string().min(1),
  name: z.string().min(1).nullable(),
  address: z.number().int().nonnegative().nullable(),
  size: z.number().int().nonnegative().nullable(),
  rva: z.number().int().nonnegative().nullable(),
  compilation_unit: z.string().min(1).nullable(),
});

const debugSectionSchema = z.strictObject({
  name: z.string().min(1),
  size: z.number().int().nonnegative(),
});

const dwarfInventorySchema = z.strictObject({
  present: z.boolean(),
  sections: z.array(debugSectionSchema),
  compilation_unit_count: z.number().int().nonnegative().nullable(),
  function_count: z.number().int().nonnegative().nullable(),
});

const pdbInventorySchema = z.strictObject({
  /** CodeView identity when the selected artifact is a PE carrying one. */
  reference: pdbReferenceSchema.nullable(),
  /** Whether the bridge's LIEF can read a PDB symbol table at all. */
  available: z.boolean(),
  public_symbol_count: z.number().int().nonnegative().nullable(),
  compilation_unit_count: z.number().int().nonnegative().nullable(),
});

const queryResultSchema = z.strictObject({
  query: liefLookupQuerySchema,
  outcome: z.enum(["found", "not_found", "unsupported"]),
  matches: z.array(liefMatchSchema),
  /** Why an `unsupported` outcome could not be answered; null otherwise. */
  reason: z.string().min(1).nullable(),
});

const lookupTruncationSchema = z.strictObject({
  queries: z.boolean(),
  matches: z.boolean(),
  dwarf_functions: z.boolean(),
});

/** Complete bounded observation of one artifact's PDB and DWARF surfaces. */
export const pdbDwarfInfoReportSchema = z
  .strictObject({
    artifact: liefArtifactSchema,
    bridge: liefBridgeAdvertisementSchema,
    artifact_kind: liefFormatSchema,
    debug_sources: z.strictObject({
      dwarf: dwarfInventorySchema,
      pdb: pdbInventorySchema,
    }),
    queries: z.array(queryResultSchema),
    truncated: lookupTruncationSchema,
    complete: z.boolean(),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    if (report.artifact_kind === "pdb" && report.debug_sources.pdb.reference)
      context.addIssue({
        code: "custom",
        path: ["debug_sources", "pdb", "reference"],
        message: "A PDB artifact carries no CodeView reference to itself.",
      });
    for (const [index, result] of report.queries.entries()) {
      const consistent =
        result.outcome === "found"
          ? result.matches.length > 0
          : result.matches.length === 0;
      if (!consistent)
        context.addIssue({
          code: "custom",
          path: ["queries", index, "matches"],
          message: "matches must be empty unless the outcome is found",
        });
      if (
        (result.outcome === "unsupported") !== (result.reason !== null) ||
        (result.outcome === "unsupported" && result.matches.length > 0)
      )
        context.addIssue({
          code: "custom",
          path: ["queries", index, "reason"],
          message:
            "only an unsupported outcome carries a reason and no matches",
        });
    }
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

export type PdbDwarfInfoReport = z.infer<typeof pdbDwarfInfoReportSchema>;
export type ExtractPdbDwarfInfoInput = z.infer<
  typeof extractPdbDwarfInfoInputSchema
>;
