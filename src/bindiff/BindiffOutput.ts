export interface ParsedBinaryDiffMatch {
  readonly primaryAddress: string;
  readonly primaryName: string | null;
  readonly secondaryAddress: string;
  readonly secondaryName: string | null;
  readonly similarity: number;
  readonly confidence: number;
}

export interface ParsedBinaryDiff {
  readonly matches: readonly ParsedBinaryDiffMatch[];
  readonly unmatchedPrimary: number;
  readonly unmatchedSecondary: number;
  readonly unparsedRows: number;
}

const asObject = (value: unknown): Record<string, unknown> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

const nonEmpty = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value.trim() : null;

const integer = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0
    ? value
    : null;

const unit = (value: unknown): number | null => {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.min(1, Math.max(0, value));
};

const addressOf = (value: unknown): string | null => {
  if (typeof value === "string" && value.trim() !== "") return value.trim();
  if (typeof value === "number" && Number.isInteger(value) && value >= 0)
    return `0x${value.toString(16)}`;
  return null;
};

const sideOf = (
  value: unknown,
): { readonly address: string; readonly name: string | null } | null => {
  const record = asObject(value);
  if (record !== null) {
    const address =
      addressOf(record.address) ??
      addressOf(record.Address) ??
      addressOf(record.va);
    return address === null
      ? null
      : {
          address,
          name: nonEmpty(record.name) ?? nonEmpty(record.Name),
        };
  }
  const address = addressOf(value);
  return address === null ? null : { address, name: null };
};

/**
 * Parse the documented BinDiff adapter JSON:
 * `{ matches: [{ primary: { address, name }, secondary: {...},
 * similarity, confidence }], unmatched_primary?, unmatched_secondary? }`.
 */
export const parseBinaryDiffJson = (
  document: Record<string, unknown>,
): ParsedBinaryDiff | null => {
  const rows = document.matches;
  if (!Array.isArray(rows)) return null;
  const matches: ParsedBinaryDiffMatch[] = [];
  let unparsedRows = 0;
  for (const row of rows) {
    const record = asObject(row);
    if (record === null) {
      unparsedRows += 1;
      continue;
    }
    const primary =
      sideOf(record.primary) ??
      sideOf({
        address: record.primary_address,
        name: record.primary_name,
      });
    const secondary =
      sideOf(record.secondary) ??
      sideOf({
        address: record.secondary_address,
        name: record.secondary_name,
      });
    const similarity = unit(record.similarity ?? record.Similarity);
    const confidence = unit(record.confidence ?? record.Confidence);
    if (
      primary === null ||
      secondary === null ||
      similarity === null ||
      confidence === null
    ) {
      unparsedRows += 1;
      continue;
    }
    matches.push({
      primaryAddress: primary.address,
      primaryName: primary.name,
      secondaryAddress: secondary.address,
      secondaryName: secondary.name,
      similarity,
      confidence,
    });
  }
  return {
    matches,
    unmatchedPrimary:
      integer(document.unmatched_primary) ??
      integer(document.unmatchedPrimary) ??
      0,
    unmatchedSecondary:
      integer(document.unmatched_secondary) ??
      integer(document.unmatchedSecondary) ??
      0,
    unparsedRows,
  };
};
