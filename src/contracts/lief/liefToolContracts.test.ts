import { describe, expect, it } from "vitest";

import { inspectBinaryDeepInputSchema } from "../../domain/lief/binaryDeep.js";
import { extractPdbDwarfInfoInputSchema } from "../../domain/lief/pdbDwarfInfo.js";
import { LIEF_TOOL_CONTRACTS } from "./liefToolContracts.js";

/** Names of the operations the registrar maps contract names onto. */
const registrarOperationNames = new Set<string>([
  "inspect_binary_deep",
  "extract_pdb_dwarf_info",
]);

const domainInputSchemas: Readonly<Record<string, unknown>> = {
  inspect_binary_deep: inspectBinaryDeepInputSchema,
  extract_pdb_dwarf_info: extractPdbDwarfInfoInputSchema,
};

describe("liefToolContracts", () => {
  it("declares the two named LIEF contracts exactly once each", () => {
    expect(LIEF_TOOL_CONTRACTS.map(({ name }) => name)).toEqual([
      "inspect_binary_deep",
      "extract_pdb_dwarf_info",
    ]);
    expect(new Set(LIEF_TOOL_CONTRACTS.map(({ name }) => name)).size).toBe(
      LIEF_TOOL_CONTRACTS.length,
    );
  });

  it("binds every contract to a real domain input schema and a registrar operation", () => {
    for (const contract of LIEF_TOOL_CONTRACTS) {
      expect(
        contract.inputSchema,
        `${contract.name} must bind its owning domain input schema`,
      ).toBe(domainInputSchemas[contract.name]);
      expect(
        registrarOperationNames.has(contract.name),
        `${contract.name} has no registered operation`,
      ).toBe(true);
    }
    expect(registrarOperationNames.size).toBe(LIEF_TOOL_CONTRACTS.length);
  });

  it("keeps inputs self-contained without $ref indirection", () => {
    for (const contract of LIEF_TOOL_CONTRACTS) {
      expect(JSON.stringify(contract.inputSchema)).not.toContain("$ref");
      expect(JSON.stringify(contract.outputSchema)).not.toContain("$ref");
    }
  });

  it("admits nonempty NUL-free artifact paths and rejects boundary values", () => {
    for (const contract of LIEF_TOOL_CONTRACTS) {
      expect(
        contract.inputSchema.safeParse({ path: "/artifacts/study" }).success,
      ).toBe(true);
      expect(contract.inputSchema.safeParse({ path: "" }).success).toBe(false);
      expect(
        contract.inputSchema.safeParse({ path: "/artifacts/a\0.elf" }).success,
      ).toBe(false);
      expect(contract.inputSchema.safeParse({}).success).toBe(false);
      expect(
        contract.inputSchema.safeParse({
          path: "/artifacts/study",
          extra: true,
        }).success,
      ).toBe(false);
    }
  });

  it("bounds lookups and rejects an unknown lookup kind", () => {
    const schema = extractPdbDwarfInfoInputSchema;
    expect(
      schema.safeParse({
        path: "/artifacts/study",
        queries: [{ kind: "symbol", name: "main" }],
      }).success,
    ).toBe(true);
    expect(
      schema.safeParse({
        path: "/artifacts/study",
        queries: Array.from({ length: 65 }, () => ({
          kind: "symbol",
          name: "main",
        })),
      }).success,
    ).toBe(false);
    expect(
      schema.safeParse({
        path: "/artifacts/study",
        queries: [{ kind: "name", name: "main" }],
      }).success,
    ).toBe(false);
    expect(
      schema.safeParse({
        path: "/artifacts/study",
        queries: [{ kind: "address", address: -1 }],
      }).success,
    ).toBe(false);
  });

  it("advertises Evidence-wrapped outputs that reject malformed payloads", () => {
    for (const contract of LIEF_TOOL_CONTRACTS) {
      expect(
        contract.outputSchema.safeParse({ normalized_result: {} }).success,
      ).toBe(false);
      expect(contract.outputSchema.safeParse(null).success).toBe(false);
    }
  });

  it("keeps every example shape aligned with its contract input schema", () => {
    for (const contract of LIEF_TOOL_CONTRACTS) {
      for (const example of contract.examples) {
        expect(
          contract.inputSchema.safeParse(example.input).success,
          example.title,
        ).toBe(true);
      }
    }
  });
});
