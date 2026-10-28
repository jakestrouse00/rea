import { z } from "zod";

import { compareAsciiStrings } from "../canonicalOrdering.js";
import {
  absoluteLocalPathStringSchema,
  nulFreeStringSchema,
} from "../localPath.js";

/** What a watch observes. Only the directory source is composed this release. */
export const huntingWatchSourceSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("directory"),
    path: absoluteLocalPathStringSchema.describe(
      "Absolute directory whose entries a change triggers re-analysis for.",
    ),
    recursive: z.boolean().default(true),
  }),
  z.strictObject({
    kind: z.literal("device"),
    identifier: nulFreeStringSchema
      .min(1)
      .describe(
        "Device the watch would observe; refused this release because no device watcher is composed.",
      ),
  }),
  z.strictObject({
    kind: z.literal("endpoint"),
    url: z
      .string()
      .url()
      .describe(
        "Endpoint the watch would poll; refused this release because no endpoint watcher is composed.",
      ),
  }),
]);
export type HuntingWatchSource = z.output<typeof huntingWatchSourceSchema>;
export type HuntingWatchSourceInput = z.input<typeof huntingWatchSourceSchema>;

/** One observed directory entry, relative to the watched root. */
export const huntingWatchEntrySchema = z.strictObject({
  path: z.string().min(1),
  bytes: z.int().min(0),
  mtime_ms: z.int().min(0),
});
export type HuntingWatchEntry = z.infer<typeof huntingWatchEntrySchema>;

/** Bounded observation of one directory tree. */
export const huntingWatchSnapshotSchema = z.strictObject({
  entries: z.array(huntingWatchEntrySchema),
  truncated: z
    .boolean()
    .describe("The entry budget stopped before it covered the tree."),
  unreadable: z
    .array(z.string().min(1))
    .describe("Relative paths the walk could not read."),
});
export type HuntingWatchSnapshot = z.infer<typeof huntingWatchSnapshotSchema>;

/** One observed change, in canonical path order. */
export interface HuntingWatchPathChange {
  readonly path: string;
  readonly change: "added" | "modified" | "removed";
}

/**
 * Compare two bounded snapshots.
 *
 * A truncated snapshot never proves absence: a path missing from it is unknown
 * rather than removed, so a bounded walk cannot turn into a deletion report.
 */
export const huntingWatchChanges = (
  previous: HuntingWatchSnapshot,
  next: HuntingWatchSnapshot,
  limit: number,
): {
  readonly changes: readonly HuntingWatchPathChange[];
  readonly truncated: boolean;
} => {
  const before = new Map(previous.entries.map((entry) => [entry.path, entry]));
  const after = new Map(next.entries.map((entry) => [entry.path, entry]));
  const removedKnown = !next.truncated;
  const changes: HuntingWatchPathChange[] = [];
  for (const [path, entry] of after) {
    const earlier = before.get(path);
    if (earlier === undefined) changes.push({ path, change: "added" });
    else if (
      earlier.bytes !== entry.bytes ||
      earlier.mtime_ms !== entry.mtime_ms
    )
      changes.push({ path, change: "modified" });
  }
  if (removedKnown)
    for (const path of before.keys())
      if (!after.has(path)) changes.push({ path, change: "removed" });
  changes.sort((left, right) => compareAsciiStrings(left.path, right.path));
  return {
    changes: changes.slice(0, limit),
    truncated: changes.length > limit || next.truncated || previous.truncated,
  };
};
