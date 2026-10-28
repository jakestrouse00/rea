import { describe, expect, it } from "vitest";

import {
  huntingWatchChanges,
  type HuntingWatchSnapshot,
} from "./huntingWatch.js";

const snapshot = (
  entries: readonly (readonly [string, number, number])[],
  options: { readonly truncated?: boolean } = {},
): HuntingWatchSnapshot => ({
  entries: entries.map(([path, bytes, mtimeMs]) => ({
    path,
    bytes,
    mtime_ms: mtimeMs,
  })),
  truncated: options.truncated ?? false,
  unreadable: [],
});

describe("hunting watch diff", () => {
  it("reports added, modified, and removed paths in canonical order", () => {
    const diff = huntingWatchChanges(
      snapshot([
        ["b.bin", 4, 1],
        ["c.bin", 4, 1],
      ]),
      snapshot([
        ["a.bin", 4, 1],
        ["c.bin", 8, 2],
      ]),
      10,
    );
    expect(diff.changes).toEqual([
      { path: "a.bin", change: "added" },
      { path: "b.bin", change: "removed" },
      { path: "c.bin", change: "modified" },
    ]);
    expect(diff.truncated).toBe(false);
  });

  it("never infers removal from a truncated observation", () => {
    const diff = huntingWatchChanges(
      snapshot([
        ["a.bin", 4, 1],
        ["b.bin", 4, 1],
      ]),
      snapshot([["a.bin", 4, 1]], { truncated: true }),
      10,
    );
    expect(diff.changes).toEqual([]);
    expect(diff.truncated).toBe(true);
  });

  it("stops at the change budget and reports the omission", () => {
    const diff = huntingWatchChanges(
      snapshot([]),
      snapshot([
        ["a.bin", 4, 1],
        ["b.bin", 4, 1],
        ["c.bin", 4, 1],
      ]),
      2,
    );
    expect(diff.changes).toEqual([
      { path: "a.bin", change: "added" },
      { path: "b.bin", change: "added" },
    ]);
    expect(diff.truncated).toBe(true);
  });
});
