import {
  crxExtensionReportSchema,
  inspectCrxExtensionInputSchema,
  inspectPyInstallerArchiveInputSchema,
  inspectXpiExtensionInputSchema,
  pyInstallerArchiveReportSchema,
  xpiExtensionReportSchema,
} from "../../domain/containers/containerReports.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/**
 * Effects for these container inspections are audited in the canonical
 * `toolEffects.ts#TOOL_EFFECTS` registry: `inspect_crx_extension` streams its
 * inner ZIP payload through an owned private temporary root
 * (`writesFilesystem`), XPI and PyInstaller parse in place.
 */
const CRX_DESCRIPTION =
  "Inspect a Chromium CRX3 browser extension package header without executing any code. Parses the Cr24 magic, protobuf CrxFileHeader (Sha256WithRsa and Sha256WithEcdsa proof entries, verified-contents and signed-header-data presence), derives the conventional crx_id, and reports the exact ZIP payload offset so downstream ZIP tooling can read the inner archive. Projects the extension manifest.json surface (name, version, manifest_version, permissions, host_permissions, background service worker or scripts, content-script matches, browser_specific_settings) as value-free metadata for the JavaScript plane. Signature validity is deliberately not verified. Reads the inner ZIP through the trusted archive reader via an owned private temporary payload copy; bounded header, manifest and entry counts with typed limit refusals.";

const XPI_DESCRIPTION =
  "Inspect a Firefox XPI browser extension package (ZIP) without executing any code. Lists META-INF/manifest.mf and META-INF/mozilla.sf per-entry SHA1 digest facts and digest-over-manifest presence as observed metadata (no signature verification), plus other META-INF signature artifacts by name and size, and projects the same value-free extension manifest.json surface including browser_specific_settings.gecko. Uses the trusted ZIP archive reader with its decompression budget; bounded entry counts and typed limit refusals.";

const PYINSTALLER_DESCRIPTION =
  "Inventory a PyInstaller CArchive (PKG) without executing or extracting entry contents. Scans for the MEI cookie (both the 24-byte PyInstaller 2.0 and 88-byte 2.1+ layouts), parses the CArchive table of contents (entry length, offsets, sizes, compression flag, type code, name) and embedded PYZ archives (header pyc magic and the marshaled TOC of (type, position, length) entries), and folds CPython 3.7-3.13 pyc header facts (magic to release line, hash-based and check-source flags, timestamp, source size or hash) into module entries whose bytes are uncompressed. Never decrypts or decompresses entry payloads; entry positions are absolute so callers can read raw bytes. Bounded TOC, TOC-entry, marshal-depth and byte budgets with typed limit refusals.";

/** Static container inspections: no processes, no network, no script execution. */
export const CONTAINER_TOOL_CONTRACTS = [
  {
    name: "inspect_crx_extension",
    kind: "artifact-provider",
    description: CRX_DESCRIPTION,
    inputSchema: inspectCrxExtensionInputSchema,
    outputSchema: evidenceResultOf(crxExtensionReportSchema),
    ...toolContractMetadata("inspect_crx_extension"),
    examples: [
      {
        title: "Inspect a CRX3 extension header and manifest surface",
        input: { path: "/artifacts/extension.crx" },
      },
    ],
  },
  {
    name: "inspect_xpi_extension",
    kind: "artifact-provider",
    description: XPI_DESCRIPTION,
    inputSchema: inspectXpiExtensionInputSchema,
    outputSchema: evidenceResultOf(xpiExtensionReportSchema),
    ...toolContractMetadata("inspect_xpi_extension"),
    examples: [
      {
        title: "Inspect XPI digests and manifest surface",
        input: { path: "/artifacts/extension.xpi" },
      },
    ],
  },
  {
    name: "inspect_pyinstaller_archive",
    kind: "artifact-provider",
    description: PYINSTALLER_DESCRIPTION,
    inputSchema: inspectPyInstallerArchiveInputSchema,
    outputSchema: evidenceResultOf(pyInstallerArchiveReportSchema),
    ...toolContractMetadata("inspect_pyinstaller_archive"),
    examples: [
      {
        title: "Inventory a PyInstaller onefile executable",
        input: { path: "/artifacts/frozen-application" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
