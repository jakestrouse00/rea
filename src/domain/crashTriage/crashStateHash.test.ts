import { fc, it } from "@fast-check/vitest";
import { describe, expect } from "vitest";

import type { CrashFrame, SanitizerClass } from "./crashReport.js";
import {
  CRASH_STATE_MAX_FRAMES,
  crashDedupIdSchema,
  crashStateFor,
  normalizeCrashFrame,
} from "./crashStateHash.js";

const frame = (
  overrides: Partial<CrashFrame> & Pick<CrashFrame, "index">,
): CrashFrame => ({
  function: null,
  module: null,
  source_file: null,
  source_line: null,
  offset: null,
  ...overrides,
});

const sourcePath = fc
  .tuple(fc.stringMatching(/^[a-z]{1,8}$/u), fc.integer({ min: 1, max: 4096 }))
  .map(([name, line]) => `/build/out/src/${name}.c:${String(line)}:7`);

const named = fc.tuple(
  fc.stringMatching(/^[a-z_][a-z0-9_]{0,14}$/u),
  fc.stringMatching(/^[a-z_][a-z0-9_]{0,14}$/u),
  fc.stringMatching(/^[a-z_][a-z0-9_]{0,14}$/u),
);

const crashTypeOf = fc.constantFrom<SanitizerClass>(
  "address",
  "thread",
  "undefined",
  "leak",
  "memory",
  "none",
);

describe("crash-state hash", () => {
  it.prop([named, sourcePath, sourcePath])(
    "ignores reported addresses, offsets, paths, and line numbers",
    ([first, second, third], pathA, pathB) => {
      const frames = [first, second, third].map((name, index) =>
        frame({ index, function: name }),
      );
      const moved = [first, second, third].map((name, index) =>
        frame({
          index,
          function: name,
          module: index === 0 ? "fuzz" : "libfuzz.dylib",
          offset: index === 0 ? 0x1000 : 0x2000,
          source_file: index === 0 ? pathA : pathB,
          source_line: index === 0 ? 42 : 43,
        }),
      );
      const base = crashStateFor({
        sanitizerClass: "address",
        crashKind: "heap-buffer-overflow",
        frames,
        maxFrames: 3,
      });
      const relocated = crashStateFor({
        sanitizerClass: "address",
        crashKind: "heap-buffer-overflow",
        frames: moved,
        maxFrames: 3,
      });
      expect(relocated.dedup_hash).toBe(base.dedup_hash);
      expect(relocated.dedup_id).toBe(base.dedup_id);
      expect(relocated.state).toBe(base.state);
    },
  );

  it.prop([named, crashTypeOf])(
    "is stable for repeated computation over the same frames",
    ([first, second, third], sanitizerClass) => {
      const frames = [first, second, third].map((name, index) =>
        frame({ index, function: name }),
      );
      const once = crashStateFor({
        sanitizerClass,
        crashKind: "data-race",
        frames,
        maxFrames: 2,
      });
      const twice = crashStateFor({
        sanitizerClass,
        crashKind: "data-race",
        frames,
        maxFrames: 2,
      });
      expect(twice).toEqual(once);
      expect(crashDedupIdSchema.safeParse(once.dedup_id).success).toBe(true);
    },
  );
});

describe("crash-state normalization and window", () => {
  it.prop([named])(
    "hashes only the chosen window and counts the rest",
    ([first, second, third]) => {
      const head = [first, second].map((name, index) =>
        frame({ index, function: name }),
      );
      const withTail = [...head, frame({ index: 2, function: third })];
      const bounded = crashStateFor({
        sanitizerClass: "address",
        crashKind: "use-after-free",
        frames: withTail,
        maxFrames: 2,
      });
      const headOnly = crashStateFor({
        sanitizerClass: "address",
        crashKind: "use-after-free",
        frames: head,
        maxFrames: 2,
      });
      expect(bounded.dedup_hash).toBe(headOnly.dedup_hash);
      expect(bounded.frames_used).toBe(2);
      expect(bounded.frames_omitted).toBe(1);
      expect(bounded.frames).toHaveLength(3);
    },
  );

  it.prop([fc.string({ minLength: 1 }), fc.string({ minLength: 1 })])(
    "separates frames that differ in their top entry",
    (left, right) => {
      const distinct = left === right ? `${right}!` : right;
      const hashOf = (name: string): string =>
        crashStateFor({
          sanitizerClass: "address",
          crashKind: "heap-buffer-overflow",
          frames: [frame({ index: 0, function: name })],
          maxFrames: 1,
        }).dedup_hash;
      expect(hashOf(left)).not.toBe(hashOf(distinct));
    },
  );

  it("separates sanitizer classes and crash kinds", () => {
    const frames = [frame({ index: 0, function: "parse_header" })];
    const address = crashStateFor({
      sanitizerClass: "address",
      crashKind: "heap-buffer-overflow",
      frames,
      maxFrames: 3,
    });
    const thread = crashStateFor({
      sanitizerClass: "thread",
      crashKind: "heap-buffer-overflow",
      frames,
      maxFrames: 3,
    });
    const otherKind = crashStateFor({
      sanitizerClass: "address",
      crashKind: "stack-buffer-overflow",
      frames,
      maxFrames: 3,
    });
    expect(thread.dedup_hash).not.toBe(address.dedup_hash);
    expect(otherKind.dedup_hash).not.toBe(address.dedup_hash);
  });

  it("normalizes argument lists, numeric suffixes, and module paths", () => {
    const templated = normalizeCrashFrame(
      frame({
        index: 0,
        function: "parse<int, std::allocator<int> >(std::vector const&)",
      }),
    );
    const otherTemplate = normalizeCrashFrame(
      frame({ index: 0, function: "parse<char>(char*)" }),
    );
    expect(templated).toBe("parse<int, std::allocator<int> >()");
    expect(otherTemplate).toBe("parse<char>()");
    expect(
      normalizeCrashFrame(frame({ index: 0, function: "GeneratedFuzz_17" })),
    ).toBe("GeneratedFuzz_N");
    expect(
      normalizeCrashFrame(
        frame({ index: 0, module: "/usr/lib/libsystem_kernel.dylib" }),
      ),
    ).toBe("libsystem_kernel.dylib");
    expect(normalizeCrashFrame(frame({ index: 0 }))).toBe("<unknown>");
    expect(
      normalizeCrashFrame(
        frame({ index: 0, function: "read(0xdeadbeef, 12)" }),
      ),
    ).toBe("read()");
  });

  it("bounds the caller's frame window", () => {
    const frames = Array.from({ length: 12 }, (_, index) =>
      frame({ index, function: `frame_${String(index)}` }),
    );
    const state = crashStateFor({
      sanitizerClass: "address",
      crashKind: "heap-buffer-overflow",
      frames,
      maxFrames: 99,
    });
    expect(state.frames_used).toBe(CRASH_STATE_MAX_FRAMES);
    expect(state.frames_omitted).toBe(12 - CRASH_STATE_MAX_FRAMES);
  });
});
