import { lstat, readdir } from "node:fs/promises";
import { join, relative, sep } from "node:path";

import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { compareAsciiStrings } from "../domain/canonicalOrdering.js";
import {
  huntingWatchEntrySchema,
  type HuntingWatchSnapshot,
} from "../domain/hunting/huntingWatch.js";
import { HUNTING_LIMITS } from "../domain/hunting/huntingLimits.js";

export interface HuntingWatchObserverOptions {
  readonly maxEntries?: number;
}

const relativePath = (root: string, path: string): string =>
  relative(root, path).split(sep).join("/");

/**
 * Walk one directory tree into a bounded snapshot.
 *
 * Only names, sizes, and modification times are retained; no file content is
 * read. A symbolic link is reported as its own entry and is never followed, so
 * a link cannot pull an outside tree into the watch. A directory the walk
 * cannot read is reported as unreadable instead of ending the walk, and the
 * entry budget stops the walk with `truncated` set.
 */
export const readHuntingWatchSnapshot = async (
  root: string,
  recursive: boolean,
  signal: AbortSignal,
  options: HuntingWatchObserverOptions = {},
): Promise<HuntingWatchSnapshot> => {
  const maxEntries = options.maxEntries ?? HUNTING_LIMITS.maxWatchEntries;
  const entries: HuntingWatchSnapshot["entries"] = [];
  const unreadable: string[] = [];
  let truncated = false;
  const pending: string[] = [root];
  while (pending.length > 0) {
    if (signal.aborted)
      throw new AnalysisCancelledError("start_watch_session", {
        cause: signal.reason,
      });
    const directory = pending.shift();
    if (directory === undefined) break;
    let children;
    try {
      children = await readdir(directory, { withFileTypes: true });
    } catch (cause: unknown) {
      if (directory === root)
        throw new AnalysisInputError(
          "start_watch_session",
          {
            cause,
            userMessage: `The watch source ${root} could not be read. Select a readable absolute directory.`,
          },
          [
            {
              path: ["source", "path"],
              reason: "invalid_value",
              message: "Expected a readable absolute directory.",
            },
          ],
        );
      unreadable.push(relativePath(root, directory));
      continue;
    }
    children.sort((left, right) => compareAsciiStrings(left.name, right.name));
    for (const child of children) {
      const absolute = join(directory, child.name);
      if (child.isDirectory()) {
        if (recursive) pending.push(absolute);
        continue;
      }
      if (entries.length >= maxEntries) {
        truncated = true;
        break;
      }
      let stats;
      try {
        stats = await lstat(absolute);
      } catch {
        unreadable.push(relativePath(root, absolute));
        continue;
      }
      entries.push(
        huntingWatchEntrySchema.parse({
          path: relativePath(root, absolute),
          bytes: stats.size,
          mtime_ms: Math.max(0, Math.trunc(stats.mtimeMs)),
        }),
      );
    }
    if (truncated) break;
  }
  entries.sort((left, right) => compareAsciiStrings(left.path, right.path));
  unreadable.sort(compareAsciiStrings);
  return { entries, truncated, unreadable };
};
