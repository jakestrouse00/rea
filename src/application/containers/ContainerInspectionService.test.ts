import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { describe, expect, it } from "vitest";

import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import {
  buildCrx3ExtensionBytes,
  buildLegacyPyInstallerBytes,
  buildPyInstallerExecutableBytes,
  buildXpiBytes,
} from "./ContainerInspectionService.fixture.js";
import { ContainerInspectionService } from "./ContainerInspectionService.js";

const service = new ContainerInspectionService();

const expectOk = <Value>(
  result: { ok: true; value: Value } | { ok: false; error: unknown },
): Value => {
  if (!result.ok)
    throw new Error(`Expected a successful result: ${String(result.error)}`);
  return result.value;
};

const writeFixture = async (
  name: string,
  bytes: Uint8Array,
): Promise<string> => {
  const directory = await createTestTempDirectory("rea-containers-");
  const path = join(directory, name);
  await writeFile(path, bytes);
  return path;
};

const notOkAs = <ErrorType extends Error>(
  result: unknown,
  errorClass: new (...args: never[]) => ErrorType,
): ErrorType => {
  const failure = result as { ok?: boolean; error?: unknown };
  expect(failure.ok).toBe(false);
  expect(failure.error).toBeInstanceOf(errorClass);
  return failure.error as ErrorType;
};

describe("inspect_crx_extension", () => {
  it("reports header facts, archive offset, and the manifest surface", async () => {
    const fixture = await buildCrx3ExtensionBytes();
    const path = await writeFixture("fixture.crx", fixture.bytes);
    const evidence = expectOk(
      await service.execute("inspect_crx_extension", { path }),
    );
    expect(evidence.provider).toMatchObject({
      id: "containers",
      name: "REA container inspector",
    });
    expect(evidence.subject).toMatchObject({
      digest: { sha256: expect.stringMatching(/^[a-f0-9]{64}$/u) },
      format: "file",
      local_path: path,
    });
    expect(evidence.locations).toContainEqual({
      kind: "file-offset",
      offset: fixture.archiveOffset,
    });
    const report = evidence.normalized_result as {
      artifact: { path: string; bytes: number };
      header: {
        crx_id: string | null;
        archive_offset: number;
        signed_header_data_bytes: number;
        proofs: {
          proof_type: string;
          public_key_bytes: number;
          signature_bytes: number;
        }[];
      };
      archive_offset: number;
      manifest: {
        name: string;
        manifest_version: number;
        permissions: string[];
        host_permissions: string[];
        background_service_worker: string;
        content_scripts: { matches: string[] }[];
      };
      archive_entry_count: number;
      limitations: string[];
    };
    expect(report.artifact.path).toBe(path);
    expect(report.header.proofs).toHaveLength(1);
    expect(report.header.proofs[0]).toMatchObject({
      proof_type: "sha256_with_rsa",
      public_key_bytes: 32,
      signature_bytes: 256,
    });
    expect(report.header.crx_id).toBe(
      createHash("sha256").update(fixture.publicKey).digest("hex").slice(0, 32),
    );
    expect(report.header.signed_header_data_bytes).toBe(
      "signed-header-data".length,
    );
    expect(report.archive_offset).toBe(fixture.archiveOffset);
    expect(report.archive_entry_count).toBe(2);
    expect(report.manifest).toMatchObject({
      name: "Fixture Extension",
      manifest_version: 3,
      permissions: ["storage"],
      host_permissions: ["*://example.com/*"],
      background_service_worker: "background.js",
    });
    expect(report.manifest?.content_scripts[0]?.matches).toEqual([
      "https://example.com/*",
    ]);
    expect(
      report.limitations.some((line) => line.includes("temporary root")),
    ).toBe(true);
  });

  it("rejects a non-CRX payload with a typed format failure", async () => {
    const path = await writeFixture("fixture.crx", Buffer.alloc(64, 1));
    const result = await service.execute("inspect_crx_extension", { path });
    expect(notOkAs(result, AnalysisInputError)).toBeDefined();
  });

  it("rejects relative and missing paths through shared validation", async () => {
    const relative = await service.execute("inspect_crx_extension", {
      path: "relative/fixture.crx",
    });
    expect(notOkAs(relative, AnalysisInputError)).toBeDefined();
    const missing = await service.execute("inspect_crx_extension", {
      path: "/nonexistent/rea-container-fixture.crx",
    });
    expect(notOkAs(missing, AnalysisInputError)).toBeDefined();
  });
});

describe("inspect_xpi_extension", () => {
  it("reports digest facts, signature-artifact presence, and gecko settings", async () => {
    const path = await writeFixture(
      "fixture.xpi",
      await buildXpiBytes({ withDigestFiles: true }),
    );
    const evidence = expectOk(
      await service.execute("inspect_xpi_extension", { path }),
    );
    const report = evidence.normalized_result as {
      manifest_mf: { entries: { name: string; sha1_digest: string }[] } | null;
      mozilla_sf: {
        digest_manifest: string;
        entries: { name: string }[];
      } | null;
      other_signature_entries: { name: string; bytes: number }[];
      manifest: {
        name: string;
        manifest_version: number;
        browser_specific_settings: {
          id: string;
          strict_min_version: string | null;
        } | null;
      } | null;
      archive_entry_count: number;
      limitations: string[];
    };
    expect(report.manifest_mf?.entries).toHaveLength(1);
    expect(report.manifest_mf?.entries[0]?.name).toBe("bg.js");
    expect(report.manifest_mf?.entries[0]?.sha1_digest).toContain("=");
    expect(report.mozilla_sf?.digest_manifest).toContain("=");
    expect(report.mozilla_sf?.entries[0]?.name).toBe("bg.js");
    expect(report.other_signature_entries).toEqual([
      { name: "META-INF/zigbert.rsa", bytes: expect.any(Number) },
    ]);
    expect(report.manifest).toMatchObject({
      name: "Fixture Firefox Add-on",
      manifest_version: 2,
    });
    expect(report.manifest?.browser_specific_settings?.id).toBe(
      "fixture@example.com",
    );
    expect(report.archive_entry_count).toBe(4);
    expect(
      report.limitations.some((line) =>
        line.includes("validity were not verified"),
      ),
    ).toBe(true);
  });

  it("defers a selected Safari .appex bundle to the Apple tool lane", async () => {
    const path = await writeFixture(
      "Fixture.appex",
      await buildXpiBytes({ withDigestFiles: false }),
    );
    const result = await service.execute("inspect_xpi_extension", { path });
    const error = notOkAs(result, AnalysisUnsupportedTargetError);
    expect(String(error)).toContain("project_apple_application_graph");
  });

  it("stays unknown when digest files are absent", async () => {
    const path = await writeFixture(
      "fixture-no-meta.xpi",
      await buildXpiBytes({ withDigestFiles: false }),
    );
    const evidence = expectOk(
      await service.execute("inspect_xpi_extension", { path }),
    );
    const report = evidence.normalized_result as {
      manifest_mf: null;
      mozilla_sf: null;
      other_signature_entries: unknown[];
      manifest: { name: string } | null;
      limitations: string[];
    };
    expect(report.manifest_mf).toBe(null);
    expect(report.mozilla_sf).toBe(null);
    expect(report.manifest?.name).toBe("Fixture Firefox Add-on");
    expect(
      report.limitations.some((line) => line.includes("META-INF/manifest.mf")),
    ).toBe(true);
  });
});

describe("inspect_pyinstaller_archive", () => {
  it("inventories cookie, TOC entries, PYZ TOC, and pyc header facts", async () => {
    const fixture = buildPyInstallerExecutableBytes();
    const path = await writeFixture("frozen-app", fixture.bytes);
    const evidence = expectOk(
      await service.execute("inspect_pyinstaller_archive", { path }),
    );
    const report = evidence.normalized_result as {
      cookie: {
        cookie_format: string;
        python_version: number;
        python_libname: string;
        archive_start: number;
      };
      toc_offset: number;
      entries: {
        name: string;
        typecode: string;
        compressed: boolean;
        encrypted: boolean;
        position: number;
        pyc_header_state: string;
        pyc_header: { python_version: string; timestamp: number } | null;
      }[];
      pyz_archives: {
        archive_position: number;
        toc_position: number;
        pyz_toc: {
          entries: {
            name: string;
            item_type: string;
            position: number;
            length: number;
          }[];
        } | null;
      }[];
      limitations: string[];
    };
    expect(report.cookie.cookie_format).toBe("pyinstaller-2.1-plus");
    expect(report.cookie.python_version).toBe(312);
    expect(report.cookie.python_libname).toBe("python312.dll");
    expect(report.toc_offset).toBeGreaterThan(report.cookie.archive_start);
    expect(report.toc_offset).toBeLessThan(fixture.cookieOffset);
    const moduleEntry = report.entries.find(
      (entry) => entry.name === "app.module",
    );
    expect(moduleEntry).toMatchObject({
      typecode: "m",
      compressed: false,
      encrypted: false,
      position: fixture.pycEntryPosition,
    });
    expect(moduleEntry?.pyc_header).toMatchObject({
      python_version: "3.12",
      timestamp: 0x04030201,
    });
    expect(moduleEntry?.pyc_header_state).toBe("parsed");
    const pyzEntry = report.entries.find((entry) => entry.name === "app.pyz");
    expect(pyzEntry?.typecode).toBe("z");
    expect(pyzEntry?.compressed).toBe(false);
    const dataEntry = report.entries.find((entry) => entry.name === "data.bin");
    expect(dataEntry).toMatchObject({ compressed: true, encrypted: false });
    const optionEntry = report.entries.find(
      (entry) => entry.name === "py-runtime-option",
    );
    expect(optionEntry?.typecode).toBe("o");
    const pyz = report.pyz_archives[0];
    expect(pyz?.archive_position).toBe(fixture.pyzEntryPosition);
    expect(pyz?.toc_position).toBe(12);
    expect(pyz?.pyz_toc?.entries).toEqual([
      {
        name: "app.main",
        item_type_code: 0,
        item_type: "module",
        position: 12,
        length: 4,
      },
      {
        name: "app.ns",
        item_type_code: 3,
        item_type: "namespace_package",
        position: 0,
        length: 0,
      },
    ]);
    expect(
      report.limitations.some((line) => line.includes("never decrypted")),
    ).toBe(true);
  });

  it("parses the legacy 2.0 cookie layout", async () => {
    const path = await writeFixture(
      "legacy-frozen-app",
      buildLegacyPyInstallerBytes(),
    );
    const evidence = expectOk(
      await service.execute("inspect_pyinstaller_archive", { path }),
    );
    const report = evidence.normalized_result as {
      cookie: {
        cookie_format: string;
        python_version: number;
        python_libname: string | null;
      };
      entries: { name: string; typecode: string }[];
    };
    expect(report.cookie.cookie_format).toBe("pyinstaller-2.0");
    expect(report.cookie.python_version).toBe(27);
    expect(report.cookie.python_libname).toBe(null);
    expect(report.entries[0]).toMatchObject({
      name: "legacy.data",
      typecode: "x",
    });
  });

  it("fails closed on a file without the CArchive cookie", async () => {
    const path = await writeFixture("not-pyinstaller", Buffer.alloc(4096, 5));
    const result = await service.execute("inspect_pyinstaller_archive", {
      path,
    });
    const error = notOkAs(result, AnalysisInputError);
    expect(JSON.stringify(error.issues)).toContain("cookie magic");
  });
});

describe("container lifecycle", () => {
  it("retains a failed runtime-root cleanup until the service close retries it", async () => {
    const fixture = await buildCrx3ExtensionBytes();
    const path = await writeFixture("fixture-lifecycle.crx", fixture.bytes);
    let closeAttempts = 0;
    const owned = await PrivateRuntimeRoot.create({
      prefix: "rea-crx-lifecycle-",
    });
    const service = new ContainerInspectionService({
      createRuntimeRoot: async () => ({
        path: owned.path,
        close: async () => {
          closeAttempts += 1;
          if (closeAttempts === 1) throw new Error("controlled cleanup fault");
          await owned.close();
        },
      }),
    });
    const result = await service.execute("inspect_crx_extension", { path });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected the cleanup fault to be reported");
    expect(result.error).toBeInstanceOf(ProviderCleanupError);
    expect(result.error.cleanupResources).toEqual([owned.path]);
    expect(closeAttempts).toBe(1);
    await service.close();
    expect(closeAttempts).toBe(2);
  });

  it("keeps caller cancellation typed and leaves nothing retained for close", async () => {
    const fixture = await buildCrx3ExtensionBytes();
    const path = await writeFixture("fixture-cancelled.crx", fixture.bytes);
    const controller = new AbortController();
    controller.abort(new Error("caller cancelled the inspection"));
    const service = new ContainerInspectionService();
    const result = await service.execute(
      "inspect_crx_extension",
      { path },
      { signal: controller.signal },
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a typed cancellation");
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    await service.close();
  });

  it("refuses a CRX3 header outside its declared read budget with a typed limit", async () => {
    // "Cr24" + version 3 + declared header size just over the 1 MiB budget.
    const declared = Buffer.alloc(4);
    declared.writeUInt32LE(1024 * 1024 + 1);
    const bytes = Buffer.concat([
      Buffer.from("Cr24", "utf8"),
      Buffer.from([3, 0, 0, 0]),
      declared,
      Buffer.alloc(64),
    ]);
    const path = await writeFixture("oversized-header.crx", bytes);
    const result = await service.execute("inspect_crx_extension", { path });
    const error = notOkAs(result, AnalysisResourceConstraintError);
    expect(String(error)).toContain("byte read budget");
    await service.close();
  });
});
