import { describe, expect, it } from "vitest";

import { parsePyzToc } from "./pyzToc.js";
import { ContainerFormatError } from "./containerFormatError.js";

const le32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeInt32LE(value, 0);
  return bytes;
};

const typeCode = (char: string, flag = false): number =>
  (flag ? 0x80 : 0) | char.charCodeAt(0);

const shortAscii = (text: string, flag = false): Buffer =>
  Buffer.concat([
    Buffer.from([typeCode("z", flag)]),
    Buffer.from([text.length]),
    Buffer.from(text, "ascii"),
  ]);

const smallTuple = (items: readonly Buffer[], flag = false): Buffer =>
  Buffer.concat([
    Buffer.from([typeCode(")", flag)]),
    Buffer.from([items.length]),
    ...items,
  ]);

const int32 = (value: number, flag = false): Buffer =>
  Buffer.concat([Buffer.from([typeCode("i", flag)]), le32(value)]);

const typeRef = (index: number): Buffer =>
  Buffer.concat([Buffer.from([typeCode("r")]), le32(index)]);

const list = (items: readonly Buffer[]): Buffer =>
  Buffer.concat([Buffer.from([typeCode("[")]), le32(items.length), ...items]);

const dict = (pairs: readonly Buffer[]): Buffer =>
  Buffer.concat([
    Buffer.from([typeCode("{")]),
    ...pairs,
    Buffer.from([typeCode("0")]),
  ]);

const listToc = (): Buffer =>
  list([
    smallTuple([
      shortAscii("module_a"),
      smallTuple([int32(0), int32(16), int32(32)]),
    ]),
    smallTuple([
      shortAscii("package_b"),
      smallTuple([int32(1), int32(64), int32(8)]),
    ]),
  ]);

const dictToc = (): Buffer =>
  dict([
    shortAscii("legacy_mod"),
    smallTuple([int32(0), int32(16), int32(24)]),
  ]);

describe("parsePyzToc", () => {
  it("parses the modern list-of-tuples TOC shape", () => {
    const parsed = parsePyzToc(listToc(), 12);
    expect(parsed.toc_position).toBe(12);
    expect(parsed.limitations).toEqual([]);
    expect(parsed.entries).toEqual([
      {
        name: "module_a",
        item_type_code: 0,
        item_type: "module",
        position: 16,
        length: 32,
      },
      {
        name: "package_b",
        item_type_code: 1,
        item_type: "package",
        position: 64,
        length: 8,
      },
    ]);
  });

  it("parses the legacy dict TOC shape including its null terminator", () => {
    const parsed = parsePyzToc(dictToc(), 0);
    expect(parsed.entries).toEqual([
      {
        name: "legacy_mod",
        item_type_code: 0,
        item_type: "module",
        position: 16,
        length: 24,
      },
    ]);
  });

  it("resolves TYPE_REF entries through the writer-ordered reference table", () => {
    // The flagged TYPE_INT is written twice; the second occurrence is a ref.
    const blob = list([
      smallTuple([
        shortAscii("shared"),
        smallTuple([int32(0, true), int32(8), int32(1)]),
      ]),
      smallTuple([
        shortAscii("module_b"),
        smallTuple([typeRef(1), int32(9), int32(1)]),
      ]),
    ]);
    const parsed = parsePyzToc(blob, 0);
    expect(parsed.entries[0]?.item_type_code).toBe(0);
    expect(parsed.entries[1]?.item_type_code).toBe(0);
    expect(parsed.entries[1]?.name).toBe("module_b");
    expect(parsed.entries[1]?.position).toBe(9);
  });

  it("rejects truncated or unsupported marshal shapes with typed failures", () => {
    expect(() => parsePyzToc(Buffer.from([0xe9]), 0)).toThrowError(
      ContainerFormatError,
    );
    expect(() => parsePyzToc(Buffer.from([0x40]), 0)).toThrowError(
      /marshal type/u,
    );
    const truncatedList = list([
      smallTuple([int32(0), int32(1), int32(1)]),
    ]).slice(0, 6);
    expect(() => parsePyzToc(truncatedList, 0)).toThrowError(
      /truncated|unexpected end/u,
    );
  });

  it("fails closed on wrong entry shapes and non-collection tops", () => {
    const wrongName = list([smallTuple([int32(0), int32(1)])]);
    expect(() => parsePyzToc(wrongName, 0)).toThrowError(
      /names must be strings/u,
    );
    const wrongEntry = list([smallTuple([shortAscii("m"), int32(1)])]);
    expect(() => parsePyzToc(wrongEntry, 0)).toThrowError(/is not a tuple/u);
    const shortEntry = list([
      smallTuple([shortAscii("m"), smallTuple([int32(0), int32(1)])]),
    ]);
    expect(() => parsePyzToc(shortEntry, 0)).toThrowError(
      /\(type, position, length\)/u,
    );
    expect(() => parsePyzToc(shortAscii("nope"), 0)).toThrowError(
      /dict or a list/u,
    );
  });

  it("keeps trailing-bytes facts as limitations", () => {
    const blob = Buffer.concat([listToc(), Buffer.from([0x69])]);
    const parsed = parsePyzToc(blob, 0);
    expect(parsed.entries).toHaveLength(2);
    expect(parsed.limitations[0]).toContain("trailing marshal bytes");
  });
});
