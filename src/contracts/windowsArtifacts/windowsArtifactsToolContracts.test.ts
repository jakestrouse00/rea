import { describe, expect, it } from "vitest";

import { inspectPdbSymbolsInputSchema } from "../../domain/windowsArtifacts/pdbSymbols.js";
import { inspectWerReportInputSchema } from "../../domain/windowsArtifacts/werReport.js";
import { inspectWindowsMinidumpInputSchema } from "../../domain/windowsArtifacts/windowsMinidump.js";
import { WINDOWS_ARTIFACTS_TOOL_CONTRACTS } from "./windowsArtifactsToolContracts.js";

/** Names of the operations record the registrar maps contract names onto. */
const registrarOperationNames = new Set<string>([
  "inspect_windows_minidump",
  "inspect_wer_report",
  "inspect_pdb_symbols",
]);

const domainInputSchemas: Readonly<Record<string, unknown>> = {
  inspect_windows_minidump: inspectWindowsMinidumpInputSchema,
  inspect_wer_report: inspectWerReportInputSchema,
  inspect_pdb_symbols: inspectPdbSymbolsInputSchema,
};

describe("windowsArtifactsToolContracts", () => {
  it("declares the three named Windows-artifact contracts exactly once each", () => {
    expect(WINDOWS_ARTIFACTS_TOOL_CONTRACTS.map(({ name }) => name)).toEqual([
      "inspect_windows_minidump",
      "inspect_wer_report",
      "inspect_pdb_symbols",
    ]);
    expect(
      new Set(WINDOWS_ARTIFACTS_TOOL_CONTRACTS.map(({ name }) => name)).size,
    ).toBe(WINDOWS_ARTIFACTS_TOOL_CONTRACTS.length);
  });

  it("binds every contract to a real domain input schema and a registrar operation", () => {
    for (const contract of WINDOWS_ARTIFACTS_TOOL_CONTRACTS) {
      expect(
        contract.inputSchema,
        `${contract.name} must bind its owning domain input schema`,
      ).toBe(domainInputSchemas[contract.name]);
      expect(
        registrarOperationNames.has(contract.name),
        `${contract.name} has no registered operation`,
      ).toBe(true);
    }
    expect(registrarOperationNames.size).toBe(
      WINDOWS_ARTIFACTS_TOOL_CONTRACTS.length,
    );
  });

  it("keeps inputs self-contained without $ref indirection", () => {
    for (const contract of WINDOWS_ARTIFACTS_TOOL_CONTRACTS) {
      expect(JSON.stringify(contract.inputSchema)).not.toContain("$ref");
      expect(JSON.stringify(contract.outputSchema)).not.toContain("$ref");
    }
  });

  it("admits nonempty NUL-free artifact paths and rejects boundary values", () => {
    for (const contract of WINDOWS_ARTIFACTS_TOOL_CONTRACTS) {
      expect(
        contract.inputSchema.safeParse({ path: "/artifacts/study" }).success,
      ).toBe(true);
      expect(contract.inputSchema.safeParse({ path: "" }).success).toBe(false);
      expect(
        contract.inputSchema.safeParse({ path: "/artifacts/App\0.wer" })
          .success,
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

  it("advertises Evidence-wrapped outputs that reject malformed payloads", () => {
    for (const contract of WINDOWS_ARTIFACTS_TOOL_CONTRACTS) {
      expect(
        contract.outputSchema.safeParse({ normalized_result: {} }).success,
      ).toBe(false);
      expect(contract.outputSchema.safeParse(null).success).toBe(false);
    }
  });

  it("keeps every example shape aligned with its contract input schema", () => {
    for (const contract of WINDOWS_ARTIFACTS_TOOL_CONTRACTS) {
      for (const example of contract.examples) {
        expect(
          contract.inputSchema.safeParse(example.input).success,
          example.title,
        ).toBe(true);
      }
    }
  });
});
