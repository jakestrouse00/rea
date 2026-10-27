import { z } from "zod";
import { canonicalBase64Schema } from "../stringPatterns.js";
import { ContainerFormatError } from "./containerFormatError.js";

/**
 * JAR-style digest manifests carried by Firefox XPI packages:
 * META-INF/manifest.mf and META-INF/mozilla.sf. Digest facts are reported as
 * observed metadata; entry-digest validity and signature verification are out
 * of scope.
 */

export const MAX_JAR_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_MANIFEST_LINE_BYTES = 8192;
const MAX_MANIFEST_SECTIONS = 65536;

const sha1DigestBase64Schema = canonicalBase64Schema;

export const jarManifestSectionSchema = z.strictObject({
  /** The section "Name" attribute value, or null for the main section. */
  name: z.string().nullable(),
  sha1_digest: sha1DigestBase64Schema.nullable(),
  /** Every digest-style attribute key observed in the section, value-free. */
  digest_attributes: z.array(z.string()),
  unrecognized_attribute_count: z.number().int().nonnegative(),
});
export type JarManifestSection = z.infer<typeof jarManifestSectionSchema>;

export const jarDigestFileSchema = z.strictObject({
  entries: z.array(jarManifestSectionSchema),
  /** The main section's digest-over-manifest attribute, when present. */
  digest_manifest: sha1DigestBase64Schema.nullable(),
  digest_manifest_attributes: z.array(z.string()),
  unrecognized_attribute_count: z.number().int().nonnegative(),
  limitations: z.array(z.string()),
});
export type JarDigestFile = z.infer<typeof jarDigestFileSchema>;

interface ManifestAttributes {
  readonly name: string | null;
  readonly attributes: ReadonlyMap<string, string>;
}

const isDigestAttribute = (key: string): boolean =>
  /-digest(?:-[a-z0-9-]*)?$/iu.test(key);

/**
 * Parse bounded JAR-manifest text into per-entry digest facts. Attribute
 * values are omitted: only digest presence, the attribute name, and the
 * digest encoding are observations.
 */
export const parseJarDigestFile = (bytes: Uint8Array): JarDigestFile => {
  if (bytes.length > MAX_JAR_MANIFEST_BYTES)
    throw new ContainerFormatError(
      "limit",
      `Digest manifest requires ${String(bytes.length)} bytes, exceeding the ${String(MAX_JAR_MANIFEST_BYTES)}-byte read budget`,
    );
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (cause: unknown) {
    throw new ContainerFormatError(
      "format",
      "Digest manifest is not valid UTF-8 text",
      { cause },
    );
  }
  // JAR manifest wraps long values: continuation lines start with a space.
  const lines: string[] = [];
  for (const rawLine of text.split(/\r?\n/u)) {
    if (rawLine.startsWith(" ") && lines.length > 0) {
      lines[lines.length - 1] += rawLine.slice(1);
      continue;
    }
    lines.push(rawLine);
  }

  const sections: ManifestAttributes[] = [];
  let current: Record<string, string> = {};
  let currentName: string | null = null;
  let unrecognizedLines = 0;
  let sectionCount = 0;
  const flush = (): void => {
    if (Object.keys(current).length === 0 && currentName === null) return;
    if (sectionCount >= MAX_MANIFEST_SECTIONS) {
      unrecognizedLines += Object.keys(current).length;
      return;
    }
    sectionCount += 1;
    sections.push({
      name: currentName,
      attributes: new Map(Object.entries(current)),
    });
    current = {};
    currentName = null;
  };
  for (const line of lines) {
    if (line === "") {
      flush();
      continue;
    }
    const separator = line.indexOf(": ");
    if (separator <= 0 || line.length > MAX_MANIFEST_LINE_BYTES) {
      unrecognizedLines += 1;
      continue;
    }
    const key = line.slice(0, separator);
    current[key] = line.slice(separator + 2);
    if (key.toLowerCase() === "name") currentName = current[key];
  }
  flush();

  const projectSection = (
    section: ManifestAttributes,
  ): JarManifestSection | null => {
    const digestKeys = [...section.attributes.keys()].filter(isDigestAttribute);
    const sha1 = section.attributes.get("SHA1-Digest");
    if (section.name === null && digestKeys.length === 0 && sha1 === undefined)
      return null;
    return {
      name: section.name,
      sha1_digest: sha1 === undefined ? null : sha1,
      digest_attributes: digestKeys,
      unrecognized_attribute_count: [...section.attributes.keys()].filter(
        (key) => !isDigestAttribute(key) && key.toLowerCase() !== "name",
      ).length,
    };
  };

  const projected = sections
    .map(projectSection)
    .filter((section): section is JarManifestSection => section !== null);
  const mainSection = sections.find((section) => section.name === null);
  const mainDigestKeys = mainSection?.attributes ?? new Map<string, string>();
  const limitations: string[] = [];
  if (unrecognizedLines > 0)
    limitations.push(
      `${String(unrecognizedLines)} unrecognized digest-manifest line(s) were skipped; only "Key: value" attribute lines are parsed.`,
    );
  return jarDigestFileSchema.parse({
    entries: projected.filter((section) => section.name !== null),
    digest_manifest: mainDigestKeys.get("SHA1-Digest-Manifest") ?? null,
    digest_manifest_attributes: [...mainDigestKeys.keys()].filter(
      isDigestAttribute,
    ),
    unrecognized_attribute_count: projected
      .filter((section) => section.name === null)
      .reduce(
        (count, section) => count + section.unrecognized_attribute_count,
        0,
      ),
    limitations,
  });
};
