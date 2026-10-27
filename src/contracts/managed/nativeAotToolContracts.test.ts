import { describe, expect, it } from "vitest";

import { NATIVE_AOT_TOOL_CONTRACTS } from "./nativeAotToolContracts.js";

const contract = NATIVE_AOT_TOOL_CONTRACTS.find(
  (entry) => entry.name === "inspect_nativeaot_types",
)!;

describe("inspect_nativeaot_types contract", () => {
  it("binds the read-only managed-provider contract with truthful derived annotations", () => {
    expect(contract.name).toBe("inspect_nativeaot_types");
    expect(contract.kind).toBe("managed-provider");
    expect(contract.title).toBe("Inspect Nativeaot Types");
    expect(contract.returnsTargetContent).toBe(true);
    expect(contract.effects).toMatchObject({
      mutatesTarget: false,
      mutatesSession: true,
      writesFilesystem: false,
      launchesProcess: false,
      accessesNetwork: false,
      executesForeignCode: false,
      idempotent: true,
    });
    expect(contract.annotations).toEqual({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    });
    expect(contract.description).toContain("ReadyToRun directory header");
    expect(contract.description).toContain("FrozenStringNode");
    expect(contract.description).toContain("explicit unknowns");
  });

  it("admits absolute paths with optional paging and rejects boundary values", () => {
    const accepted = contract.inputSchema.safeParse({
      path: "/tmp/App.exe",
      offset: 0,
      limit: 1000,
    });
    expect(accepted.success).toBe(true);

    for (const input of [
      {},
      { path: "relative/App.exe" },
      { path: "/tmp/App\0.exe" },
      { path: "/tmp/App.exe", offset: -1 },
      { path: "/tmp/App.exe", limit: 0 },
      { path: "/tmp/App.exe", limit: 1001 },
      { path: "/tmp/App.exe", unrelated: true },
    ]) {
      expect(contract.inputSchema.safeParse(input).success).toBe(false);
    }
  });

  it("advertises an Evidence-wrapped normalized result that rejects malformed payloads", () => {
    const rejected = contract.outputSchema.safeParse({ normalized_result: {} });
    expect(rejected.success).toBe(false);
    const rejectedEmpty = contract.outputSchema.safeParse(null);
    expect(rejectedEmpty.success).toBe(false);
  });

  it("keeps a single example shape aligned with the input schema", () => {
    for (const example of contract.examples) {
      expect(
        contract.inputSchema.safeParse(example.input).success,
        example.title,
      ).toBe(true);
    }
  });
});
