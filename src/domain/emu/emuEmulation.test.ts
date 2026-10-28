import { expect, test } from "vitest";

import {
  assembleBytesInputSchema,
  assembleBytesResultSchema,
  emulateFunctionInputSchema,
  emulateFunctionResultSchema,
  emuBridgeIdentitySchema,
  emuRequestSchema,
} from "./emuEmulation.js";
import { emuBridgeResponseSchema } from "./emuBridgeProtocol.js";

const baseResult = {
  bridge: { protocol: 1, unicorn_version: "2.1.4", keystone_version: null },
  arch: "x86_64",
  endianness: "little",
  code: {
    source: "hex",
    path: null,
    offset: null,
    length: 4,
    sha256: "0".repeat(64),
  },
  code_base: "0x100000",
  entry: "0x100000",
  exit: "returned",
  exit_detail: { code: "sentinel_return", address: "0x200000" },
  executed_steps: 4,
  call_count: 0,
  call_targets: [],
  call_targets_truncated: false,
  edges: ["0x100000->0x100004"],
  edge_count: 1,
  edges_truncated: false,
  registers: [{ name: "rax", value: "0x1" }],
  unknown_registers: [],
  memory: [{ address: "0x100000", length: 4, sha256: "a".repeat(64) }],
  memory_omitted: 0,
  coverage: "complete",
} as const;

test("applies the emulation defaults a caller may omit", () => {
  const parsed = emulateFunctionInputSchema.parse({
    arch: "x86_64",
    source: { kind: "hex", hex: "c3" },
  });
  expect(parsed).toMatchObject({
    arch: "x86_64",
    endianness: "little",
    code_base: "0x100000",
    entry_offset: 0,
    stack_size: 65_536,
    args: [],
    max_steps: 100_000,
    timeout_ms: 10_000,
    stop_addresses: [],
    observe_registers: [],
    observe_memory: [],
  });
  const file = emulateFunctionInputSchema.parse({
    arch: "mips32",
    endianness: "big",
    source: { kind: "file", path: "/artifacts/app.bin", length: 64 },
  });
  expect(file.source).toEqual({
    kind: "file",
    path: "/artifacts/app.bin",
    offset: 0,
    length: 64,
  });
});

test("refuses unknown architectures, relative paths, and out-of-range bounds", () => {
  expect(
    emulateFunctionInputSchema.safeParse({
      arch: "riscv64",
      source: { kind: "hex", hex: "c3" },
    }).success,
  ).toBe(false);
  expect(
    emulateFunctionInputSchema.safeParse({
      arch: "x86_64",
      source: { kind: "file", path: "app.bin", length: 4 },
    }).success,
  ).toBe(false);
  expect(
    emulateFunctionInputSchema.safeParse({
      arch: "x86_64",
      source: { kind: "hex", hex: "c3" },
      max_steps: 5_000_001,
    }).success,
  ).toBe(false);
  expect(
    emulateFunctionInputSchema.safeParse({
      arch: "x86_64",
      source: { kind: "hex", hex: "C3" },
    }).success,
  ).toBe(false);
  expect(
    emulateFunctionInputSchema.safeParse({
      arch: "x86_64",
      source: { kind: "hex", hex: "c3" },
      observe_memory: [{ address: "0x1000", length: 65_537 }],
    }).success,
  ).toBe(false);
});

test("validates one bounded emulation result and refuses extra facts", () => {
  expect(emulateFunctionResultSchema.parse(baseResult)).toEqual(baseResult);
  expect(
    emulateFunctionResultSchema.safeParse({ ...baseResult, code_bytes: "c3" })
      .success,
  ).toBe(false);
  expect(
    emulateFunctionResultSchema.safeParse({ ...baseResult, executed_steps: -1 })
      .success,
  ).toBe(false);
  expect(
    emulateFunctionResultSchema.safeParse({ ...baseResult, exit: "crashed" })
      .success,
  ).toBe(false);
  expect(
    emulateFunctionResultSchema.safeParse({
      ...baseResult,
      edges: ["0x100000"],
    }).success,
  ).toBe(false);
  expect(
    emulateFunctionResultSchema.safeParse({
      ...baseResult,
      memory: [
        {
          address: "0x1000",
          length: 4,
          sha256: "a".repeat(64),
          bytes_hex: "c3",
        },
      ],
    }).success,
  ).toBe(false);
});

test("validates one assembly result and its optional statement count", () => {
  const result = {
    bridge: {
      protocol: 1,
      unicorn_version: "2.1.4",
      keystone_version: "0.9.2",
    },
    arch: "x86_64",
    endianness: "little",
    base_address: "0x0",
    assembly: "ret",
    bytes_hex: "c3",
    size: 1,
    sha256: "b".repeat(64),
    instruction_count: null,
  };
  expect(assembleBytesResultSchema.parse(result)).toEqual(result);
  expect(
    assembleBytesResultSchema.safeParse({ ...result, bytes_hex: "c" }).success,
  ).toBe(false);
  expect(
    assembleBytesInputSchema.parse({ arch: "x86_64", assembly: "ret" }),
  ).toMatchObject({ endianness: "little", base_address: "0x0" });
  expect(
    assembleBytesInputSchema.safeParse({ arch: "x86_64", assembly: "" })
      .success,
  ).toBe(false);
});

test("requires the pinned protocol in the bridge identity", () => {
  expect(
    emuBridgeIdentitySchema.safeParse({
      protocol: 2,
      unicorn_version: "2.1.4",
      keystone_version: null,
    }).success,
  ).toBe(false);
  expect(
    emuBridgeResponseSchema.safeParse({
      protocol: 1,
      job_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      kind: "emulate",
      ok: false,
      error: { code: "missing_dependency", message: "no unicorn" },
    }).success,
  ).toBe(true);
  expect(
    emuBridgeResponseSchema.safeParse({
      protocol: 1,
      job_id: "not-a-uuid",
      kind: "emulate",
      ok: true,
    }).success,
  ).toBe(false);
});

test("keeps each operation bound to its own input schema", () => {
  expect(
    emuRequestSchema.safeParse({
      operation: "assemble_bytes",
      input: { arch: "x86_64", assembly: "ret" },
    }).success,
  ).toBe(true);
  expect(
    emuRequestSchema.safeParse({
      operation: "assemble_bytes",
      input: { arch: "x86_64", assembly: "ret", max_steps: 1 },
    }).success,
  ).toBe(false);
  expect(
    emuRequestSchema.safeParse({
      operation: "emulate_function_isolated",
      input: { arch: "x86_64", source: { kind: "hex", hex: "c3" } },
    }).success,
  ).toBe(true);
});
