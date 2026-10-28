import {
  MAX_YARA_MATCH_LOCATIONS,
  MAX_YARA_MATCHES,
} from "../domain/yara/yaraScan.js";

export interface YaraFieldMatch {
  readonly identifier: string;
  readonly offset: number;
  readonly length: number;
}

export interface YaraRuleMatch {
  readonly ruleId: string;
  readonly namespace: string | null;
  readonly tags: readonly string[];
  readonly fields: readonly YaraFieldMatch[];
  readonly unparsedFields: number;
}

export interface YaraInventory {
  readonly matches: readonly YaraRuleMatch[];
  readonly unparsedEntries: number;
  readonly truncated: boolean;
}

const nonEmpty = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value.trim() : null;

const integer = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0
    ? value
    : null;

const asObject = (value: unknown): Record<string, unknown> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

/** Read a YARA-X match row, accepting the `rule_id` and `rule` spellings. */
const ruleMatchOf = (
  value: unknown,
): YaraRuleMatch | { readonly unparsed: true } => {
  const record = asObject(value);
  if (record === null) return { unparsed: true };
  const ruleId =
    nonEmpty(record.rule_id) ?? nonEmpty(record.rule) ?? nonEmpty(record.name);
  if (ruleId === null) return { unparsed: true };
  const fields: YaraFieldMatch[] = [];
  let unparsedFields = 0;
  const matches = record.matches;
  if (Array.isArray(matches)) {
    for (const entry of matches) {
      const field = asObject(entry);
      if (field === null) {
        unparsedFields += 1;
        continue;
      }
      const identifier =
        nonEmpty(field.identifier) ??
        nonEmpty(field.name) ??
        nonEmpty(field.field);
      const offset = integer(field.offset);
      const length = integer(field.length);
      if (identifier === null || offset === null || length === null) {
        unparsedFields += 1;
        continue;
      }
      fields.push({ identifier, offset, length });
    }
  }
  const tags = Array.isArray(record.tags)
    ? record.tags.flatMap((tag) => {
        const parsed = nonEmpty(tag);
        return parsed === null ? [] : [parsed];
      })
    : [];
  const publishedFields = fields.slice(0, MAX_YARA_MATCH_LOCATIONS);
  return {
    ruleId,
    namespace: nonEmpty(record.namespace),
    tags,
    fields: publishedFields,
    unparsedFields: unparsedFields + fields.length - publishedFields.length,
  };
};

/**
 * Parse the `yr scan --output-format=json` array. YARA-X writes one array
 * element per matching rule; a match's `data` bytes are never read here.
 */
export const parseYaraJson = (stdout: string): YaraInventory | null => {
  const document = parseJsonDocument(stdout);
  if (document === null) return null;
  const rows = Array.isArray(document) ? document : asObject(document)?.matches;
  if (!Array.isArray(rows)) return null;
  let unparsedEntries = 0;
  const matches: YaraRuleMatch[] = [];
  for (const row of rows) {
    const parsed = ruleMatchOf(row);
    if ("unparsed" in parsed) {
      unparsedEntries += 1;
      continue;
    }
    matches.push(parsed);
    unparsedEntries += parsed.unparsedFields;
  }
  return {
    matches: matches
      .sort((left, right) =>
        left.ruleId < right.ruleId ? -1 : left.ruleId > right.ruleId ? 1 : 0,
      )
      .slice(0, MAX_YARA_MATCHES),
    unparsedEntries,
    truncated: matches.length > MAX_YARA_MATCHES,
  };
};

/** Parse stdout, tolerating a leading diagnostic line before the JSON body. */
const parseJsonDocument = (stdout: string): unknown => {
  const trimmed = stdout.trim();
  if (trimmed === "") return [];
  const direct = tryParse(trimmed);
  if (direct !== undefined) return direct;
  const arrayStart = trimmed.indexOf("[");
  if (arrayStart > 0) {
    const embedded = tryParse(trimmed.slice(arrayStart));
    if (embedded !== undefined) return embedded;
  }
  const objectStart = trimmed.indexOf("{");
  if (objectStart > 0) {
    const embedded = tryParse(trimmed.slice(objectStart));
    if (embedded !== undefined) return embedded;
  }
  return null;
};

const tryParse = (value: string): unknown => {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
};
