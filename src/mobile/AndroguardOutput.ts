import type { z } from "zod";

import type { mobileToolchainResultSchemas } from "../domain/mobile/mobileToolchain.js";
import { err, ok, type Result } from "../domain/result.js";

/** The bridge's own document version; a different one is not reinterpreted. */
export const ANDROGUARD_BRIDGE_SCHEMA = "rea.androguard.v1";

type ApkStructureFacts = Omit<
  z.infer<(typeof mobileToolchainResultSchemas)["analyze_apk_structure"]>,
  "client" | "apk" | "elapsed_ms" | "coverage"
>;

type ApkVulnerabilityFacts = Omit<
  z.infer<(typeof mobileToolchainResultSchemas)["scan_apk_vulnerabilities"]>,
  "client" | "apk" | "elapsed_ms" | "coverage"
>;

const stringOrNull = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

const intOrNull = (value: unknown): number | null =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;

const stringsOf = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter(
        (entry): entry is string =>
          typeof entry === "string" && entry.length > 0,
      )
    : [];

const COMPONENT_KINDS = new Set([
  "activity",
  "service",
  "receiver",
  "provider",
]);

/**
 * Read the bridge's single JSON document. A bridge error document and an
 * unrecognized schema are distinct refusals; neither is treated as an empty
 * inventory.
 */
export const parseAndroguardDocument = (
  stdout: string,
): Result<Record<string, unknown>, string> => {
  const lines = stdout
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (lines.length === 0) return err("the androguard bridge printed nothing");
  let document: unknown;
  try {
    document = JSON.parse(lines[lines.length - 1]!);
  } catch {
    return err("the androguard bridge's last line was not JSON");
  }
  if (document === null || typeof document !== "object")
    return err("the androguard bridge's document is not a JSON object");
  const fields = document as Record<string, unknown>;
  if (fields.schema !== ANDROGUARD_BRIDGE_SCHEMA)
    return err(
      `the androguard bridge reported schema ${String(fields.schema)}, not ${ANDROGUARD_BRIDGE_SCHEMA}`,
    );
  const error = stringOrNull(fields.error);
  if (error !== null) return err(error);
  return ok(fields);
};

/** Project the bridge's structure document into the tool's retained facts. */
export const androguardStructureOf = (
  document: Readonly<Record<string, unknown>>,
  limits: {
    readonly maxComponents: number;
    readonly maxCrossReferences: number;
  },
): ApkStructureFacts => {
  const components = Array.isArray(document.components)
    ? document.components
        .map((entry) => {
          const row =
            entry !== null && typeof entry === "object"
              ? (entry as Record<string, unknown>)
              : {};
          const kind = stringOrNull(row.kind);
          const name = stringOrNull(row.name);
          if (kind === null || name === null || !COMPONENT_KINDS.has(kind))
            return null;
          return {
            kind: kind as "activity" | "service" | "receiver" | "provider",
            name,
            exported: typeof row.exported === "boolean" ? row.exported : null,
          };
        })
        .filter((row): row is NonNullable<typeof row> => row !== null)
    : [];
  const crossReferences = Array.isArray(document.cross_references)
    ? document.cross_references
        .map((entry) => {
          const row =
            entry !== null && typeof entry === "object"
              ? (entry as Record<string, unknown>)
              : {};
          const from = stringOrNull(row.from);
          const to = stringOrNull(row.to);
          const count = intOrNull(row.count);
          if (from === null || to === null || count === null || count === 0)
            return null;
          return { from, to, count };
        })
        .filter((row): row is NonNullable<typeof row> => row !== null)
    : [];
  const reportedComponents = intOrNull(document.component_count);
  const reportedCrossReferences = intOrNull(document.cross_reference_count);
  const componentsTruncated =
    document.components_truncated === true ||
    components.length > limits.maxComponents;
  const crossReferencesTruncated =
    document.cross_references_truncated === true ||
    crossReferences.length > limits.maxCrossReferences;
  return {
    package: stringOrNull(document.package),
    app_name: stringOrNull(document.app_name),
    version_name: stringOrNull(document.version_name),
    version_code: stringOrNull(document.version_code),
    min_sdk: intOrNull(document.min_sdk),
    target_sdk: intOrNull(document.target_sdk),
    permissions: stringsOf(document.permissions),
    components: components.slice(0, limits.maxComponents),
    component_count: reportedComponents ?? components.length,
    components_truncated: componentsTruncated,
    cross_references: crossReferences.slice(0, limits.maxCrossReferences),
    cross_reference_count: reportedCrossReferences ?? crossReferences.length,
    cross_references_truncated: crossReferencesTruncated,
    native_libraries: stringsOf(document.native_libraries),
    unparsed_facts: intOrNull(document.unparsed_facts) ?? 0,
    warnings: stringsOf(document.warnings),
  };
};

const SEVERITIES = new Set(["info", "warning", "high"]);

/** Project the bridge's finding rows; ids and locations only, never evidence. */
export const androguardFindingsOf = (
  document: Readonly<Record<string, unknown>>,
  maxFindings: number,
): ApkVulnerabilityFacts => {
  const findings = Array.isArray(document.findings)
    ? document.findings
        .map((entry) => {
          const row =
            entry !== null && typeof entry === "object"
              ? (entry as Record<string, unknown>)
              : {};
          const id = stringOrNull(row.id);
          const severity = stringOrNull(row.severity);
          const location = stringOrNull(row.location);
          if (
            id === null ||
            severity === null ||
            location === null ||
            !SEVERITIES.has(severity)
          )
            return null;
          return {
            id,
            severity: severity as "info" | "warning" | "high",
            location,
          };
        })
        .filter((row): row is NonNullable<typeof row> => row !== null)
    : [];
  const reported = intOrNull(document.finding_count) ?? findings.length;
  return {
    findings: findings.slice(0, maxFindings),
    finding_count: reported,
    findings_truncated:
      document.findings_truncated === true || findings.length > maxFindings,
  };
};
