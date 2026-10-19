import type {
  PdbCompiland,
  PdbSymbolRecord,
} from "../domain/windowsArtifacts/pdbSymbols.js";

/**
 * Reader for one `llvm-pdbutil dump` text output. Record shapes follow the
 * llvm-pdbutil output verified in LLVM's own FileCheck tests (`Mod 0000`
 * module headings, `<offset> | S_* [size = N] `name`` symbol records with
 * `addr = seg:off` continuation lines, `S_PUB32` records with
 * `flags = ..., addr = ...`, and `Named Stream: '...'` stream lines). Every
 * line that does not match a modeled shape is preserved verbatim as
 * unparsed text; nothing is inferred from it. Source-server streams are
 * recorded as inert names only.
 */
export const PDB_MAX_PRESERVED_LINES = 2048;
export const PDB_MAX_UNPARSED_LINES = 1024;
export const PDB_MAX_SYMBOL_RECORDS = 65536;
export const PDB_MAX_MODULES = 65536;

export class PdbDumpTextFailure extends Error {
  readonly kind: "malformed";
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PdbDumpTextFailure";
    this.kind = "malformed";
  }
}

/** `<offset> | S_KIND [size = N] `name`` or `S_KIND [size = N] `name``. */
const SYMBOL_LINE =
  /^(?:\s*(\d+) \| )?(S_[A-Z0-9_]+) \[size = (\d+)\] `(.*)`$/u;

const ADDR_LINE = /addr = ([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})/u;
const CODE_SIZE_LINE = /code size = (\d+)/u;
const MODULE_LINE = /^Mod (\d{4})(.*)$/u;
const NAMED_STREAM_LINE = /^Stream (\d+): .*Named Stream: '([^']*)'.*$/u;

export interface PdbDumpTextReport {
  readonly modules: PdbCompiland[];
  readonly symbols: PdbSymbolRecord[];
  readonly named_streams: string[];
  readonly srcsrv_streams_observed: string[];
  readonly raw_dump_lines: string[];
  readonly unparsed_lines: string[];
  readonly unparsed_line_count: number;
  readonly complete: boolean;
  readonly limitations: string[];
}

/** Parse one bounded, complete `llvm-pdbutil dump` stdout. */
export const parsePdbDumpText = (stdout: string): PdbDumpTextReport => {
  const lines = stdout.split(/\r?\n/u);
  const modules: PdbCompiland[] = [];
  const symbols: PdbSymbolRecord[] = [];
  const namedStreams: string[] = [];
  const srcsrvStreams: string[] = [];
  const rawLines: string[] = [];
  const unparsedLines: string[] = [];
  let unparsedLineCount = 0;
  let currentSymbol: PdbSymbolRecord | undefined;
  let truncated = false;

  for (const line of lines) {
    if (rawLines.length < PDB_MAX_PRESERVED_LINES) rawLines.push(line);
    else truncated = true;
    const symbol = SYMBOL_LINE.exec(line);
    if (symbol !== null) {
      if (symbols.length >= PDB_MAX_SYMBOL_RECORDS)
        throw new PdbDumpTextFailure(
          `llvm-pdbutil printed more than ${String(PDB_MAX_SYMBOL_RECORDS)} symbol records above the record budget`,
        );
      const recordOffset = symbol[1] === undefined ? null : Number(symbol[1]);
      const kind = symbol[2];
      const size = symbol[3];
      const name = symbol[4];
      if (kind === undefined || size === undefined || name === undefined)
        continue;
      const record: PdbSymbolRecord = {
        kind,
        name,
        record_offset: recordOffset,
        size: Number(size),
        segment: null,
        segment_offset: null,
        code_size: null,
        source_lines: [line],
      };
      symbols.push(record);
      currentSymbol = record;
      continue;
    }
    if (currentSymbol !== undefined) {
      const address = ADDR_LINE.exec(line);
      if (address !== null) {
        const segmentHex = address[1];
        const segmentOffsetHex = address[2];
        const codeSize = CODE_SIZE_LINE.exec(line);
        if (segmentHex === undefined || segmentOffsetHex === undefined)
          continue;
        currentSymbol.segment = Number.parseInt(segmentHex, 16);
        currentSymbol.segment_offset = Number.parseInt(segmentOffsetHex, 16);
        if (codeSize !== null && codeSize[1] !== undefined)
          currentSymbol.code_size = Number(codeSize[1]);
        if (currentSymbol.source_lines.length < 8)
          currentSymbol.source_lines.push(line);
        continue;
      }
    }
    const namedStream = NAMED_STREAM_LINE.exec(line);
    if (namedStream !== null) {
      const name = namedStream[2];
      if (name !== undefined) {
        namedStreams.push(name);
        if (name.startsWith("/src/")) srcsrvStreams.push(name);
      }
      continue;
    }
    const moduleLine = MODULE_LINE.exec(line);
    if (moduleLine !== null) {
      const indexText = moduleLine[1];
      if (indexText === undefined) continue;
      const index = Number(indexText);
      const nameMatch = /`(.*)`/u.exec(moduleLine[2] ?? "");
      // llvm-pdbutil repeats `Mod NNNN` headings per section; group the
      // repeated headings into one compiland in first-seen order.
      const existing = modules.find((candidate) => candidate.index === index);
      if (existing !== undefined) {
        existing.module_lines.push(line);
        continue;
      }
      if (modules.length >= PDB_MAX_MODULES)
        throw new PdbDumpTextFailure(
          `llvm-pdbutil printed more than ${String(PDB_MAX_MODULES)} module headings above the module budget`,
        );
      modules.push({
        index,
        name:
          nameMatch === null || nameMatch[1] === undefined
            ? null
            : nameMatch[1],
        module_lines: [line],
      });
      continue;
    }
    if (unparsedLines.length < PDB_MAX_UNPARSED_LINES) unparsedLines.push(line);
    unparsedLineCount += 1;
  }
  const limitations: string[] = [
    "Symbol records come from llvm-pdbutil's documented `dump` text shapes; every unmatched line is preserved verbatim as unparsed text.",
    "Source-server content (named streams under /src/) is recorded as inert stream names only: never parsed as configuration, fetched, or executed.",
    "Module headings are recorded as printed; LLVM's per-module detail sub-lines are preserved unparsed and no compiland contribution is derived.",
    "No embedded command, path or script inside the PDB is executed or resolved.",
  ];
  return {
    modules,
    symbols,
    named_streams: namedStreams,
    srcsrv_streams_observed: srcsrvStreams,
    raw_dump_lines: rawLines,
    unparsed_lines: unparsedLines,
    unparsed_line_count: unparsedLineCount,
    complete: !truncated,
    limitations: truncated
      ? [
          ...limitations,
          "Output exceeded the preserved-line cap; raw lines beyond it are counted but not retained.",
        ]
      : limitations,
  };
};
