import { z } from "zod";

import {
  MAX_CAPA_RULE_LOCATIONS,
  MAX_CAPA_RULES,
} from "../domain/capa/capaAnalysis.js";

const jsonObjectSchema = z.record(z.string(), z.unknown());
const unknownArraySchema = z.array(z.unknown());

export interface CapaAttack {
  readonly id: string | null;
  readonly tactic: string | null;
  readonly technique: string | null;
}

export interface CapaMbc {
  readonly id: string | null;
  readonly objective: string | null;
  readonly behavior: string | null;
}

export interface CapaRule {
  readonly id: string;
  readonly namespace: string | null;
  readonly scope: string | null;
  readonly authors: readonly string[];
  readonly attack: readonly CapaAttack[];
  readonly mbc: readonly CapaMbc[];
  readonly matchCount: number;
  readonly locations: readonly string[];
}

export interface CapaInventory {
  readonly format: string | null;
  readonly arch: string | null;
  readonly os: string | null;
  readonly rules: readonly CapaRule[];
  readonly unparsedEntries: number;
  readonly truncated: boolean;
}

const nonEmpty = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value.trim() : null;

const integer = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0
    ? value
    : null;

const stringList = (value: unknown): readonly string[] =>
  Array.isArray(value)
    ? value
        .filter(
          (entry): entry is string =>
            typeof entry === "string" && entry.trim() !== "",
        )
        .map((entry) => entry.trim())
    : [];

/** Parse one ATT&CK or MBC entry from the `id`/`parts`/`tactic` shapes capa uses. */
const techniqueOf = (
  value: unknown,
): { readonly id: string | null; readonly parts: readonly string[] } => {
  if (typeof value === "string") return { id: null, parts: [value] };
  if (typeof value !== "object" || value === null)
    return { id: null, parts: [] };
  const record = value as Record<string, unknown>;
  const parts = stringList(record.parts ?? record.technique);
  return {
    id: nonEmpty(record.id),
    parts: parts.length > 0 ? parts : stringList(record.tactic),
  };
};

const attackOf = (value: unknown): CapaAttack | null => {
  if (typeof value === "string")
    return { id: null, tactic: null, technique: nonEmpty(value) };
  const parsed = techniqueOf(value);
  if (parsed.id === null && parsed.parts.length === 0) return null;
  return {
    id: parsed.id,
    tactic: parsed.parts[0] ?? null,
    technique: parsed.parts.at(-1) ?? null,
  };
};

const mbcOf = (value: unknown): CapaMbc | null => {
  if (typeof value === "string")
    return { id: null, objective: null, behavior: nonEmpty(value) };
  const parsed = techniqueOf(value);
  if (parsed.id === null && parsed.parts.length === 0) return null;
  return {
    id: parsed.id,
    objective: parsed.parts[0] ?? null,
    behavior: parsed.parts.at(-1) ?? null,
  };
};

const collectionOf = <T>(
  value: unknown,
  parse: (entry: unknown) => T | null,
): readonly T[] =>
  Array.isArray(value)
    ? value.flatMap((entry) => {
        const parsed = parse(entry);
        return parsed === null ? [] : [parsed];
      })
    : [];

/** Read rule matches across the address-keyed and array document shapes. */
export const matchLocationsOf = (value: unknown): readonly string[] => {
  if (typeof value === "number") return [];
  if (Array.isArray(value))
    return value.flatMap((entry) => {
      if (typeof entry === "string" && entry.trim() !== "")
        return [entry.trim()];
      if (typeof entry !== "object" || entry === null) return [];
      const record = entry as Record<string, unknown>;
      for (const key of ["location", "address", "function", "name"]) {
        const located = nonEmpty(record[key]);
        if (located !== null) return [located];
      }
      // capa 7+ emits one object per match keyed by address: {"0x401000": {...}}
      const keys = Object.keys(record).filter((key) => key.trim() !== "");
      return keys.length === 1 ? keys : [];
    });
  if (typeof value === "object" && value !== null)
    return Object.keys(value).filter((key) => key.trim() !== "");
  return [];
};

const scopeOf = (meta: Record<string, unknown>): string | null => {
  const scopes = meta.scopes;
  if (typeof scopes === "string") return nonEmpty(scopes);
  if (Array.isArray(scopes)) return nonEmpty(scopes[0]);
  if (typeof scopes === "object" && scopes !== null) {
    const record = scopes as Record<string, unknown>;
    // Newer capa reports a per-scope count map; the first declared scope names
    // the rule's primary scope.
    const first = Object.keys(record)[0];
    return nonEmpty(first);
  }
  return nonEmpty(meta.scope);
};

const ruleOf = (
  key: string,
  value: unknown,
): CapaRule | { readonly unparsed: true } => {
  if (typeof value !== "object" || value === null) return { unparsed: true };
  const rule = value as Record<string, unknown>;
  const meta =
    typeof rule.meta === "object" && rule.meta !== null
      ? (rule.meta as Record<string, unknown>)
      : {};
  const id = nonEmpty(meta.name) ?? nonEmpty(key);
  if (id === null) return { unparsed: true };
  const locations = matchLocationsOf(rule.matches);
  const declaredCount = integer(rule.matches);
  return {
    id,
    namespace: nonEmpty(meta.namespace),
    scope: scopeOf(meta),
    authors: stringList(meta.authors),
    attack: collectionOf(meta.attack, attackOf),
    mbc: collectionOf(meta.mbc, mbcOf),
    matchCount: declaredCount ?? locations.length,
    locations: locations.slice(0, MAX_CAPA_RULE_LOCATIONS),
  };
};

/** Parse one capa JSON document into a structural rule inventory. */
export const parseCapaJson = (
  document: Record<string, unknown>,
): CapaInventory | null => {
  const rulesValue = document.rules;
  if (typeof rulesValue !== "object" || rulesValue === null) return null;
  let unparsedEntries = 0;
  let rules: CapaRule[] = [];
  if (Array.isArray(rulesValue)) {
    for (const entry of unknownArraySchema.parse(rulesValue)) {
      if (typeof entry !== "object" || entry === null) {
        unparsedEntries += 1;
        continue;
      }
      const record = entry as Record<string, unknown>;
      const key = nonEmpty(record.name) ?? "";
      const parsed = ruleOf(key, entry);
      if ("unparsed" in parsed) unparsedEntries += 1;
      else rules.push(parsed);
    }
  } else {
    for (const [key, entry] of Object.entries(
      jsonObjectSchema.parse(rulesValue),
    )) {
      const parsed = ruleOf(key, entry);
      if ("unparsed" in parsed) unparsedEntries += 1;
      else rules.push(parsed);
    }
  }
  const truncated = rules.length > MAX_CAPA_RULES;
  rules = rules
    .sort((left, right) =>
      left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
    )
    .slice(0, MAX_CAPA_RULES);
  const analysis =
    typeof document.meta === "object" && document.meta !== null
      ? (document.meta as Record<string, unknown>).analysis
      : undefined;
  const analysisRecord =
    typeof analysis === "object" && analysis !== null
      ? (analysis as Record<string, unknown>)
      : {};
  return {
    format:
      nonEmpty(analysisRecord.format) ?? nonEmpty(analysisRecord.file_format),
    arch: nonEmpty(analysisRecord.arch),
    os: nonEmpty(analysisRecord.os),
    rules,
    unparsedEntries,
    truncated,
  };
};
