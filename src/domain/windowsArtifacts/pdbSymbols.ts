import { z } from "zod";
import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

/** Absolute filesystem path and stable identity of one selected PDB. */
export const inspectPdbSymbolsInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the selected PDB file",
  ),
});

/** One module/compiland heading observed in the dump output. */
export const pdbCompilandSchema = z.strictObject({
  index: z.number().int().nonnegative(),
  /** Backticked module name when the heading carries one; null otherwise. */
  name: z.string().nullable(),
  /** Raw heading lines are preserved verbatim as recorded text. */
  module_lines: z.array(z.string()),
});

/** One parsed CodeView symbol record with its segment:offset facts. */
export const pdbSymbolRecordSchema = z.strictObject({
  kind: z.string().min(1),
  name: z.string().nullable(),
  /** Leading record offset when the line carries one, as a nonnegative integer. */
  record_offset: z.number().int().nonnegative().nullable(),
  size: z.number().int().nonnegative().nullable(),
  segment: z.number().int().nonnegative().nullable(),
  segment_offset: z.number().int().nonnegative().nullable(),
  code_size: z.number().int().nonnegative().nullable(),
  /** Raw record lines, including continuation lines, preserved verbatim. */
  source_lines: z.array(z.string()),
});

/** The bounded, ordered invocation that produced this observation. */
export const pdbInvocationSchema = z.strictObject({
  command: z.string().min(1),
  arguments: z.array(z.string()),
  exit: z.number().int().nonnegative(),
  stdout_bytes: z.number().int().nonnegative(),
  stderr_bytes: z.number().int().nonnegative(),
});

/**
 * Complete bounded observation of one `llvm-pdbutil dump` run. Everything the
 * dump printed is either a parsed record below or preserved in
 * `unparsed_lines`; nothing is inferred from the surrounding text.
 */
export const pdbSymbolsSchema = z
  .strictObject({
    artifact: z.strictObject({
      path: localPathStringSchema,
      sha256: digestSchema,
      bytes: z.number().int().nonnegative(),
    }),
    invocation: pdbInvocationSchema,
    modules: z.array(pdbCompilandSchema),
    symbols: z.array(pdbSymbolRecordSchema),
    /** Named-stream names observed in the `-streams` section, verbatim. */
    named_streams: z.array(z.string()),
    /**
     * Streams whose names look like source-server content (`/src/...`). REA
     * records them as inert text only: never parsed as configuration, never
     * fetched, and never executed.
     */
    srcsrv_streams_observed: z.array(z.string()),
    srcsrv_executed: z.literal(false),
    raw_dump_lines: z.array(z.string()),
    unparsed_lines: z.array(z.string()),
    /** Total unmatched lines, including any beyond the preserved cap. */
    unparsed_line_count: z.number().int().nonnegative(),
    complete: z.boolean(),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    if (report.srcsrv_streams_observed.length > 0)
      for (const [index, name] of report.srcsrv_streams_observed.entries())
        if (!report.named_streams.includes(name))
          context.addIssue({
            code: "custom",
            path: ["srcsrv_streams_observed", index],
            message:
              "Source-server stream names must be observed named streams.",
          });
  });

export type PdbCompiland = z.infer<typeof pdbCompilandSchema>;
export type PdbSymbolRecord = z.infer<typeof pdbSymbolRecordSchema>;
export type PdbSymbols = z.infer<typeof pdbSymbolsSchema>;
export type InspectPdbSymbolsInput = z.infer<
  typeof inspectPdbSymbolsInputSchema
>;
