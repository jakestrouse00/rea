import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { MOBILE_LIMITS } from "./MobileToolchainRelease.js";

/** One TSV table as the tool wrote it, before REA bounds anything. */
export interface ForensicTsvFile {
  readonly name: string;
  readonly bytes: number;
  readonly sha256: string;
}

/** One parsed table, bounded at the parse boundary. */
export interface ParsedForensicTable {
  readonly name: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly columns: readonly string[];
  readonly rows: readonly (readonly string[])[];
  readonly rowCount: number;
  readonly retainedRows: number;
  readonly truncated: boolean;
}

export interface ForensicParseLimits {
  readonly maxTables: number;
  readonly maxRowsPerTable: number;
}

/**
 * Parse one iLEAPP/ALEAPP TSV table. The first non-empty line is the header;
 * every later line is one row. A row with a different column count keeps its
 * cells as printed and is counted, not repaired. Cells longer than the
 * per-cell bound are truncated and the table is marked partial.
 */
export const parseForensicTsv = (
  file: ForensicTsvFile,
  content: string,
  limits: { readonly maxRows: number },
): ParsedForensicTable => {
  let columns: string[] = [];
  const rows: string[][] = [];
  let rowCount = 0;
  let truncated = false;
  let sawHeader = false;
  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.replace(/\r$/u, "");
    if (line.trim().length === 0) continue;
    const cells = line.split("\t");
    if (!sawHeader) {
      sawHeader = true;
      columns = cells.map((cell) => cell.trim());
      continue;
    }
    rowCount += 1;
    if (rows.length >= limits.maxRows) {
      truncated = true;
      continue;
    }
    rows.push(
      cells.map((cell) => {
        if (cell.length <= MOBILE_LIMITS.forensicCellCharacters) return cell;
        truncated = true;
        return cell.slice(0, MOBILE_LIMITS.forensicCellCharacters);
      }),
    );
  }
  if (!sawHeader) truncated = true;
  return {
    name: file.name,
    sha256: file.sha256,
    bytes: file.bytes,
    columns,
    rows,
    rowCount,
    retainedRows: rows.length,
    truncated,
  };
};

export const isForensicTableName = (name: string): boolean =>
  /\.tsv$/iu.test(name);

/**
 * Enumerate and read the tables a report run wrote. Listing is deterministic
 * (sorted by name); the file-count and total-byte bounds are applied before
 * any file is read, and an unreadable table is reported as an unparsed file
 * rather than silently omitted.
 */
export const collectForensicTables = async (
  directory: string,
  limits: ForensicParseLimits,
): Promise<{
  readonly tables: readonly ParsedForensicTable[];
  readonly unparsedFiles: readonly string[];
  readonly truncated: boolean;
  readonly totalRows: number;
}> => {
  let names: string[];
  try {
    names = (await readdir(directory)).filter(isForensicTableName).sort();
  } catch {
    return { tables: [], unparsedFiles: [], truncated: false, totalRows: 0 };
  }
  const tables: ParsedForensicTable[] = [];
  const unparsedFiles: string[] = [];
  let truncated = names.length > limits.maxTables;
  let totalBytes = 0;
  for (const name of names.slice(0, limits.maxTables)) {
    const path = join(directory, name);
    try {
      const facts = await stat(path);
      if (!facts.isFile()) {
        unparsedFiles.push(name);
        continue;
      }
      if (facts.size > MOBILE_LIMITS.forensicTableBytes) {
        unparsedFiles.push(name);
        truncated = true;
        continue;
      }
      if (totalBytes + facts.size > MOBILE_LIMITS.forensicTotalBytes) {
        truncated = true;
        break;
      }
      const bytes = await readFile(path);
      totalBytes += bytes.byteLength;
      tables.push(
        parseForensicTsv(
          {
            name,
            bytes: bytes.byteLength,
            sha256: createHash("sha256").update(bytes).digest("hex"),
          },
          bytes.toString("utf8"),
          { maxRows: limits.maxRowsPerTable },
        ),
      );
    } catch {
      unparsedFiles.push(name);
    }
  }
  return {
    tables,
    unparsedFiles,
    truncated: truncated || tables.some((table) => table.truncated),
    totalRows: tables.reduce((total, table) => total + table.rowCount, 0),
  };
};
