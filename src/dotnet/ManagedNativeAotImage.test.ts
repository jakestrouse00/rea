import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

import { inspectManagedNativeAotBytes } from "./ManagedNativeAotImage.js";
import { buildManagedNativeAotPeFixture } from "./ManagedNativeAotPe.fixture.js";
import type {
  NativeAotArtifactInspection,
  NativeAotInspectionRow,
} from "../domain/managed/nativeAotArtifact.js";

const inspect = (bytes: Buffer) =>
  inspectManagedNativeAotBytes(
    createHash("sha256").update(bytes).digest("hex"),
    bytes,
  );

const findRow = <Kind extends NativeAotInspectionRow["kind"]>(
  result: NativeAotArtifactInspection,
  kind: Kind,
  fileOffset: number,
): Extract<NativeAotInspectionRow, { kind: Kind }> | null =>
  result.rows.find(
    (row): row is Extract<NativeAotInspectionRow, { kind: Kind }> =>
      row.kind === kind && row.file_offset === fileOffset,
  ) ?? null;

// oxlint-disable-next-line max-lines-per-function -- golden assertions share one fixture instance; splitting them would re-parse the same bytes without new semantics.
describe("managed NativeAOT structural inspection", () => {
  // oxlint-disable-next-line max-lines-per-function -- one golden assertion set shares the fixture instance; splitting it would re-parse the same bytes without new semantics.
  it("recovers the documented ReadyToRun directory, MethodTables, and frozen strings with exact artifact-relative identities", () => {
    const fixture = buildManagedNativeAotPeFixture();
    const result = inspect(fixture.bytes);

    expect(result.status).toBe("complete");
    expect(result.reason).toBeNull();
    expect(result.artifact.byte_length).toBe(fixture.bytes.length);
    expect(result.pe).toEqual({
      machine: 0x014c,
      machine_hex: "0x014c",
      architecture: "x86",
      image_base: "0x400000",
      pointer_size: 4,
    });

    const headerSignal = result.detection.find(
      (signal) => signal.signal === "readytorun-header",
    );
    expect(headerSignal?.status).toBe("present");
    expect(headerSignal?.file_offset).toBe(fixture.rtrHeaderOffset);
    expect(headerSignal?.va).toBe(fixture.rtrHeaderVa);
    expect(
      result.detection.find(
        (signal) => signal.signal === "readytorun-cli-signature",
      )?.status,
    ).toBe("absent");
    expect(
      result.detection.find(
        (signal) => signal.signal === "dotnet-runtime-debug-header-export",
      )?.status,
    ).toBe("absent");
    expect(
      result.detection.find((signal) => signal.signal === "managed-section")
        ?.status,
    ).toBe("present");

    expect(result.readytorun_header).not.toBeNull();
    if (result.readytorun_header === null) throw new Error("header missing");
    const header = result.readytorun_header;
    expect(header.major_version).toBe(9);
    expect(header.minor_version).toBe(1);
    expect(header.entry_layout).toBe("nativeaot-module");
    expect(header.entry_size).toBe(24);
    expect(header.entry_type).toBe(1);
    expect(header.format_hint).toContain("ReadyToRun 9.1");
    expect(header.sections.map((section) => section.type)).toEqual([206, 204]);
    expect(header.sections[0]?.type_name).toBe("FrozenObjectRegion");
    expect(header.sections[1]?.type_name).toBe("TypeManagerIndirection");
    expect(header.sections[0]?.start_file_offset).not.toBeNull();
    expect(header.sections[0]?.start_va).not.toBeNull();

    expect(result.paging).toEqual({
      offset: 0,
      limit: result.rows.length,
      total_rows: result.rows.length,
      returned_rows: result.rows.length,
      complete: true,
    });

    const objectRow = findRow(
      result,
      "method-table",
      fixture.methodTableOffsets.objectMt,
    );
    expect(objectRow).toMatchObject({
      kind: "method-table",
      element_type: "class",
      base_size: 0x0c,
      related_type: null,
      related_type_file_offset: null,
      vtable_slot_count: 3,
      interface_count: 0,
    });
    expect(objectRow?.va).not.toBeNull();
    const stringRow = findRow(
      result,
      "method-table",
      fixture.methodTableOffsets.stringMt,
    );
    expect(stringRow).toMatchObject({
      kind: "method-table",
      base_size: 0x0e,
      related_type_file_offset: fixture.methodTableOffsets.objectMt,
      vtable_slot_count: 3,
    });
    const interfaceRow = findRow(
      result,
      "method-table",
      fixture.methodTableOffsets.interfaceMt,
    );
    expect(interfaceRow).toMatchObject({
      kind: "method-table",
      vtable_slot_count: 0,
      interface_count: 1,
      related_type_file_offset: fixture.methodTableOffsets.objectMt,
    });
    const classRow = findRow(
      result,
      "method-table",
      fixture.methodTableOffsets.classMt,
    );
    expect(classRow).toMatchObject({
      kind: "method-table",
      base_size: 0x10,
      vtable_slot_count: 1,
      interface_count: 1,
    });

    const firstString = findRow(
      result,
      "frozen-string",
      fixture.frozenStringOffsets[0]!,
    );
    expect(firstString).toMatchObject({
      kind: "frozen-string",
      char_length: 17,
      value: "Hello, NativeAOT!",
    });
    expect(firstString?.data_file_offset).toBe(
      fixture.frozenStringOffsets[0]! + 8,
    );
    const secondString = findRow(
      result,
      "frozen-string",
      fixture.frozenStringOffsets[1]!,
    );
    expect(secondString).toMatchObject({
      kind: "frozen-string",
      char_length: 3,
      value: "abc",
    });

    expect(result.rows.map((row) => row.index)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(result.rows.map((row) => row.file_offset)).toEqual([
      ...[
        fixture.methodTableOffsets.objectMt,
        fixture.methodTableOffsets.stringMt,
        fixture.methodTableOffsets.interfaceMt,
        fixture.methodTableOffsets.classMt,
      ].sort((left, right) => left - right),
      ...[...fixture.frozenStringOffsets].sort((left, right) => left - right),
    ]);

    expect(result.coverage).toMatchObject({
      sentinel_scan_bytes_omitted: 0,
      sentinel_candidates: 1,
      validated_readytorun_candidates: 1,
      method_tables_recovered: 4,
      frozen_strings_recovered: 2,
      rows_omitted: 0,
      truncated: false,
    });
    expect(result.limitations).toContain(
      "Rows are structural candidates recovered by the documented MethodTable and frozen-String layouts; original managed type names, method identities, and runtime type-system identities are not recovered by this lane.",
    );
    expect(result.limitations).toContain(
      "The dehydrated-data hydration interpreter (ReadyToRun section type 207, dotnet 8+ metadata rehydration) is not implemented, so metadata that exists only inside the runtime-hydrated overlay is not recovered.",
    );
  });

  it("reports the DehydratedData section as an explicit unknown without dropping recovered rows", () => {
    const fixture = buildManagedNativeAotPeFixture({ dehydratedSection: true });
    const result = inspect(fixture.bytes);
    expect(result.status).toBe("complete");
    expect(
      result.readytorun_header?.sections.map((section) => section.type),
    ).toEqual([206, 204, 207]);
    expect(result.limitations).toContain(
      "The ReadyToRun directory contains a DehydratedData section (type 207); hydrated runtime metadata is not recovered by this lane.",
    );
    expect(result.limitations).toContain(
      "The ReadyToRun directory contains a TypeManagerIndirection section (type 204); the module header it points to is not parsed (version-divergent), so module-level metadata stays unknown.",
    );
    expect(result.coverage.method_tables_recovered).toBe(4);
    expect(result.coverage.frozen_strings_recovered).toBe(2);
  });

  it("detects the DotNetRuntimeDebugHeader export without claiming structural identity", () => {
    const fixture = buildManagedNativeAotPeFixture({ debugHeaderExport: true });
    const result = inspect(fixture.bytes);
    const exportSignal = result.detection.find(
      (signal) => signal.signal === "dotnet-runtime-debug-header-export",
    );
    expect(exportSignal?.status).toBe("present");
    expect(exportSignal?.file_offset).toBe(fixture.exportNameOffset);
    expect(exportSignal?.va).not.toBeNull();
  });

  it("keeps ambiguous sentinel matches unknown instead of selecting a directory", () => {
    const fixture = buildManagedNativeAotPeFixture({
      duplicateDirectory: true,
    });
    const result = inspect(fixture.bytes);
    expect(result.status).toBe("partial");
    expect(result.reason).toContain("selection would be a guess");
    expect(result.readytorun_header).toBeNull();
    const signal = result.detection.find(
      (candidate) => candidate.signal === "readytorun-header",
    );
    expect(signal?.status).toBe("uncertain");
    expect(result.coverage.validated_readytorun_candidates).toBe(2);
    expect(result.coverage.truncated).toBe(true);
  });

  it("treats an unvalidatable sentinel as uncertain and reports absence without guessing", () => {
    const corrupt = buildManagedNativeAotPeFixture({ corruptEntrySize: true });
    const corruptResult = inspect(corrupt.bytes);
    const corruptSignal = corruptResult.detection.find(
      (candidate) => candidate.signal === "readytorun-header",
    );
    expect(corruptSignal?.status).toBe("uncertain");
    expect(corruptSignal?.detail).toContain("1 RTR sentinel matches");
    expect(corruptResult.readytorun_header).toBeNull();
    expect(corruptResult.status).toBe("complete");

    const plain = buildManagedNativeAotPeFixture({
      noDirectory: true,
      plainDataSectionName: true,
    });
    const plainResult = inspect(plain.bytes);
    const plainSignal = plainResult.detection.find(
      (candidate) => candidate.signal === "readytorun-header",
    );
    expect(plainSignal?.status).toBe("absent");
    expect(plainResult.readytorun_header).toBeNull();
    expect(plainResult.limitations).toContain(
      "No ReadyToRun directory, DotNetRuntimeDebugHeader export, .managed section, or CLI ReadyToRun signature was found; absence of the documented indicators does not establish that the binary is not NativeAOT (indicators can be stripped).",
    );
  });

  it("keeps the .managed section signal tied to the exact section name", () => {
    const plainData = buildManagedNativeAotPeFixture({
      plainDataSectionName: true,
    });
    const result = inspect(plainData.bytes);
    expect(
      result.detection.find((signal) => signal.signal === "managed-section")
        ?.status,
    ).toBe("absent");
    expect(
      result.detection.find((signal) => signal.signal === "readytorun-header")
        ?.status,
    ).toBe("present");
  });

  it("documents the CoreCLR ReadyToRun plane as outside NativeAOT structural recovery", () => {
    const fixture = buildManagedNativeAotPeFixture({ coreclrLayout: true });
    const result = inspect(fixture.bytes);
    expect(result.readytorun_header?.entry_layout).toBe("coreclr-readytorun");
    expect(result.readytorun_header?.entry_size).toBe(12);
    expect(result.limitations).toContain(
      "The validated ReadyToRun directory uses the CoreCLR ReadyToRun entry layout (RVA/size sections); NativeAOT structural recovery does not apply to that directory plane, so no rows are recovered from it.",
    );
  });

  it("reports not-applicable for bytes that are not an admitted PE image", () => {
    const result = inspect(Buffer.from("not a PE image at all"));
    expect(result.status).toBe("not-applicable");
    expect(result.reason).toEqual(expect.any(String));
    expect(result.pe).toBeNull();
    expect(result.rows).toEqual([]);
    expect(result.limitations[0]).toContain(
      "not admitted as a PE image by the shared managed PE reader",
    );
  });
});
