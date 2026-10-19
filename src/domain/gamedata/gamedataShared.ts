import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

/** Stable artifact identity shared by every game-container report. */
export const gamedataArtifactSchema = z.strictObject({
  path: localPathStringSchema,
  sha256: digestSchema,
  bytes: z.number().int().nonnegative(),
});

/** Deterministic paging defaults shared by long entry inventories. */
export const GAMEDATA_PAGE_DEFAULTS = {
  entries_start: 0,
  entries_limit: 200,
} as const;

/** Deterministic paging inputs for long entry lists. */
export const gamedataPageSchema = z.strictObject({
  entries_start: z
    .number()
    .int()
    .min(0)
    .default(GAMEDATA_PAGE_DEFAULTS.entries_start),
  entries_limit: z
    .number()
    .int()
    .min(1)
    .max(500)
    .default(GAMEDATA_PAGE_DEFAULTS.entries_limit),
});

/** Paged slice projection shared by entry inventories. */
export const pagedSliceSchema = z.strictObject({
  entry_total: z.number().int().nonnegative(),
  entry_start: z.number().int().nonnegative(),
  entry_returned: z.number().int().nonnegative(),
  complete: z.boolean(),
});

/** Slice one ordered collection while preserving exact examined counts. */
export const sliceEntries = <T>(
  values: readonly T[],
  start: number,
  limit: number,
): { entries: T[]; slice: z.infer<typeof pagedSliceSchema> } => {
  const startApplied = Math.min(start, values.length);
  const entries = values.slice(startApplied, startApplied + limit);
  return {
    entries,
    slice: {
      entry_total: values.length,
      entry_start: startApplied,
      entry_returned: entries.length,
      complete: startApplied + entries.length >= values.length,
    },
  };
};
