import { z } from "zod";
import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";
import { crx3HeaderSchema } from "./crxHeader.js";
import { webExtensionManifestSchema } from "./webExtensionManifest.js";
import { jarDigestFileSchema } from "./jarManifestDigests.js";
import { pyinstallerInventorySchema } from "./pyinstallerArchive.js";

/** Exact local artifact identity shared by every container operation. */
export const containerArtifactSchema = z.strictObject({
  path: localPathStringSchema,
  sha256: digestSchema,
  bytes: z.number().int().nonnegative(),
});

const containerInputMember = {
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the selected container file",
  ),
};

export const inspectCrxExtensionInputSchema =
  z.strictObject(containerInputMember);
export const inspectXpiExtensionInputSchema =
  z.strictObject(containerInputMember);
export const inspectPyInstallerArchiveInputSchema =
  z.strictObject(containerInputMember);

/** CRX₃ header, ZIP payload offset, and the inner extension manifest surface. */
export const crxExtensionReportSchema = z.strictObject({
  artifact: containerArtifactSchema,
  header: crx3HeaderSchema,
  /** Offset where the CRX3 archive section starts; the existing ZIP reader consumes it. */
  archive_offset: z.number().int().nonnegative(),
  manifest: webExtensionManifestSchema.nullable(),
  archive_entry_count: z.number().int().nonnegative().nullable(),
  limitations: z.array(z.string()),
});

const xpiSignatureEntrySchema = z.strictObject({
  name: z.string().min(1),
  bytes: z.number().int().nonnegative(),
});

/** XPI META-INF digest facts and the shared extension manifest surface. */
export const xpiExtensionReportSchema = z.strictObject({
  artifact: containerArtifactSchema,
  manifest_mf: jarDigestFileSchema.nullable(),
  mozilla_sf: jarDigestFileSchema.nullable(),
  /** Other META-INF signature artifacts, presence and size only. */
  other_signature_entries: z.array(xpiSignatureEntrySchema),
  manifest: webExtensionManifestSchema.nullable(),
  archive_entry_count: z.number().int().nonnegative().nullable(),
  limitations: z.array(z.string()),
});

/** CArchive/PYZ inventory with pyc header facts folded in per entry. */
export const pyInstallerArchiveReportSchema = z.strictObject({
  artifact: containerArtifactSchema,
  cookie: pyinstallerInventorySchema.shape.cookie,
  toc_offset: pyinstallerInventorySchema.shape.toc_offset,
  entries: pyinstallerInventorySchema.shape.entries,
  pyz_archives: pyinstallerInventorySchema.shape.pyz_archives,
  limitations: pyinstallerInventorySchema.shape.limitations,
});
