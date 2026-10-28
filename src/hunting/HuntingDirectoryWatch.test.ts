import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { readHuntingWatchSnapshot } from "./HuntingDirectoryWatch.js";

const controller = () => new AbortController();

describe("directory watch observation", () => {
  it("retains names, sizes, and modification times without reading content", async () => {
    const root = await createTestTempDirectory("hunting-watch-");
    await mkdir(join(root, "nested"), { recursive: true });
    await writeFile(join(root, "target.bin"), "ABCD");
    await writeFile(join(root, "nested", "notes.txt"), "hello");
    const snapshot = await readHuntingWatchSnapshot(
      root,
      true,
      controller().signal,
    );
    expect(snapshot.entries.map((entry) => entry.path)).toEqual([
      "nested/notes.txt",
      "target.bin",
    ]);
    expect(snapshot.entries[1]?.bytes).toBe(4);
    expect(snapshot.truncated).toBe(false);
    expect(snapshot.unreadable).toEqual([]);
  });

  it("reports the entry budget as a truncation instead of a complete walk", async () => {
    const root = await createTestTempDirectory("hunting-watch-");
    await writeFile(join(root, "a.bin"), "a");
    await writeFile(join(root, "b.bin"), "b");
    const snapshot = await readHuntingWatchSnapshot(
      root,
      true,
      controller().signal,
      {
        maxEntries: 1,
      },
    );
    expect(snapshot.entries).toHaveLength(1);
    expect(snapshot.truncated).toBe(true);
  });

  it("reports an unreadable subtree without ending the walk", async () => {
    const root = await createTestTempDirectory("hunting-watch-");
    const locked = join(root, "locked");
    await mkdir(locked);
    await chmod(locked, 0o000);
    await writeFile(join(root, "target.bin"), "a");
    const snapshot = await readHuntingWatchSnapshot(
      root,
      true,
      controller().signal,
    );
    await chmod(locked, 0o700);
    expect(snapshot.entries.map((entry) => entry.path)).toEqual(["target.bin"]);
    expect(snapshot.unreadable).toEqual(["locked"]);
  });

  it("refuses an unreadable root and an aborted observation", async () => {
    const root = await createTestTempDirectory("hunting-watch-");
    await expect(
      readHuntingWatchSnapshot(join(root, "absent"), true, controller().signal),
    ).rejects.toMatchObject({ _tag: "AnalysisInputError" });
    const aborted = new AbortController();
    aborted.abort("caller stopped");
    await expect(
      readHuntingWatchSnapshot(root, true, aborted.signal),
    ).rejects.toMatchObject({ _tag: "AnalysisCancelledError" });
  });
});
