import {
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  mitmControlDocument,
  writeMitmControlFile,
  type MitmControlFileOperations,
} from "./MitmRuleControl.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

const directory = async (): Promise<string> => {
  const root = await createTestTempDirectory("mitm-control-");
  roots.push(root);
  return root;
};

const rule = {
  ruleId: "0b4f5d4c-1a52-4f7f-9a0e-9f9a1a0b3c4d",
  match: {
    origins: ["https://api.example.test"],
    pathPrefixes: ["/v1"],
    methods: ["GET"],
  },
  action: {
    kind: "request" as const,
    setHeaders: [{ name: "x-probe", value: "1" }],
    removeHeaders: ["if-none-match"],
    setQuery: [{ name: "debug", value: "1" }],
    removeQuery: ["cache"],
    bodyBase64: "e30=",
  },
  expiresAtMs: 1_800_000_000_000,
};

describe("mitm rule control file", () => {
  it("writes an owner-only revision with the values the addon applies", async () => {
    const root = await directory();
    const path = join(root, "rules.json");
    const written = await writeMitmControlFile(
      path,
      3,
      mitmControlDocument(3, [rule]),
    );
    expect(written.revision).toBe(3);
    expect(written.sha256).toMatch(/^[a-f0-9]{64}$/u);
    const document = JSON.parse(await readFile(path, "utf8")) as {
      revision: number;
      rules: Record<string, unknown>[];
    };
    expect(document.revision).toBe(3);
    expect(document.rules[0]).toMatchObject({
      rule_id: rule.ruleId,
      phase: "request",
      action: {
        kind: "request",
        set_headers: [["x-probe", "1"]],
        remove_headers: ["if-none-match"],
        set_query: [["debug", "1"]],
        remove_query: ["cache"],
        body_base64: "e30=",
      },
    });
    if (process.platform !== "win32")
      expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("removes its temporary file when a write fails and the retry succeeds", async () => {
    const root = await directory();
    const path = join(root, "rules.json");
    const failingOpen = async (
      target: string,
      flags: string,
      mode: number,
    ): Promise<FileHandle> => {
      const handle = await open(target, flags, mode);
      return {
        writeFile: async () => {
          await handle.close();
          throw new Error("ENOSPC");
        },
        sync: async () => undefined,
        close: async () => undefined,
      } as unknown as FileHandle;
    };
    const operations = {
      open: failingOpen,
      rename,
      unlink,
    } as unknown as MitmControlFileOperations;
    await expect(
      writeMitmControlFile(path, 1, mitmControlDocument(1, [rule]), operations),
    ).rejects.toThrow("ENOSPC");
    expect(await readdir(root)).toEqual([]);
    const retried = await writeMitmControlFile(
      path,
      1,
      mitmControlDocument(1, [rule]),
    );
    expect(retried.revision).toBe(1);
    expect(JSON.parse(await readFile(path, "utf8"))).toMatchObject({
      revision: 1,
    });
  });

  it("does not collide with a stale fixed-name temporary file", async () => {
    const root = await directory();
    const path = join(root, "rules.json");
    const stale = join(root, `.rules.json.${String(process.pid)}.tmp`);
    await writeFile(stale, "stale", { mode: 0o600 });
    const written = await writeMitmControlFile(
      path,
      2,
      mitmControlDocument(2, []),
    );
    expect(written.revision).toBe(2);
    expect(await readFile(stale, "utf8")).toBe("stale");
    expect(JSON.parse(await readFile(path, "utf8"))).toMatchObject({
      revision: 2,
      rules: [],
    });
  });
});
