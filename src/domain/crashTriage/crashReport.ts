import { z } from "zod";

import type { JsonValue } from "../jsonValue.js";

/** Provider identity for crash reports REA parsed from a caller-run engine. */
export const CRASH_TRIAGE_PROVIDER = {
  id: "rea-crash-triage",
  name: "REA crash triage",
  version: "1",
} as const;

/** Recognized report families. Compilers emit one style per sanitizer runtime. */
export const CRASH_REPORT_FORMATS = [
  "asan",
  "tsan",
  "ubsan",
  "lsan",
  "msan",
  "macos-ips",
  "macos-text",
] as const;

export const crashReportFormatSchema = z.enum(CRASH_REPORT_FORMATS);
export type CrashReportFormat = z.infer<typeof crashReportFormatSchema>;

/** Sanitizer runtime that produced the report, or none for an OS crash report. */
export const SANITIZER_CLASSES = [
  "address",
  "thread",
  "undefined",
  "leak",
  "memory",
  "none",
] as const;

export const sanitizerClassSchema = z.enum(SANITIZER_CLASSES);
export type SanitizerClass = z.infer<typeof sanitizerClassSchema>;

const SANITIZER_CLASS_OF_FORMAT: Readonly<
  Record<CrashReportFormat, SanitizerClass>
> = {
  asan: "address",
  tsan: "thread",
  ubsan: "undefined",
  lsan: "leak",
  msan: "memory",
  "macos-ips": "none",
  "macos-text": "none",
};

/** Frames retained from one report; longer reports keep their top frames. */
export const CRASH_REPORT_MAX_FRAMES = 512;

/** Characters retained from the sanitizer's own one-line summary. */
export const CRASH_REPORT_MAX_SUMMARY_CHARS = 200;

/** Longest accepted report body; a larger file is a caller-admission problem. */
export const CRASH_REPORT_MAX_BYTES = 4 * 1024 * 1024;

/**
 * Characters retained from one reported frame text field.
 *
 * A symbol, module, or source path is a short identifier in every real
 * symbolizer output. Anything longer is either a corrupted line or a hostile
 * report, and it would otherwise place report bytes in an inline tool reply
 * that has its own response budget.
 */
export const CRASH_REPORT_MAX_FRAME_CHARS = 512;

/** Characters retained from one short report label (exception type, signal). */
export const CRASH_REPORT_MAX_LABEL_CHARS = 128;

/** Memory access a sanitizer reported, when the runtime names one. */
export const crashAccessSchema = z.enum(["read", "write", "read-write"]);

export type CrashAccess = z.infer<typeof crashAccessSchema>;

/**
 * One reported stack frame, as the report spelled it.
 *
 * Addresses and module offsets are kept for reference but never hashed: the
 * crash-state hash drops them, so the same crash yields the same state under
 * ASLR, a different module load address, or a different build path.
 */
export const crashFrameSchema = z.strictObject({
  index: z
    .int()
    .min(0)
    .describe("Frame number as the report spelled it, not an array position."),
  function: z
    .string()
    .min(1)
    .max(CRASH_REPORT_MAX_FRAME_CHARS)
    .nullable()
    .describe(
      "Reported symbol, or null when the report carried none. Clipped to the frame text budget, with text_truncated set on the frame when it was.",
    ),
  module: z
    .string()
    .min(1)
    .max(CRASH_REPORT_MAX_FRAME_CHARS)
    .nullable()
    .describe("Reported image or module basename, or null when unstated."),
  source_file: z
    .string()
    .min(1)
    .max(CRASH_REPORT_MAX_FRAME_CHARS)
    .nullable()
    .describe(
      "Source path the sanitizer symbolizer printed, when it printed one.",
    ),
  source_line: z.int().min(1).nullable(),
  offset: z
    .int()
    .min(0)
    .nullable()
    .describe("Byte offset the report printed with the frame."),
  text_truncated: z
    .boolean()
    .describe(
      "A text field on this frame was clipped to the report text budget.",
    ),
});

export type CrashFrame = z.infer<typeof crashFrameSchema>;

/**
 * Structural facts one report establishes.
 *
 * `crash_kind` is a normalized token derived from the runtime's own error
 * type, so two builds that report the same defect classify together. The full
 * report body is never part of these facts: it stays on disk and is identified
 * by its digest.
 */
export const crashReportFactsSchema = z.strictObject({
  format: crashReportFormatSchema,
  sanitizer_class: sanitizerClassSchema,
  crash_kind: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/u),
  access: crashAccessSchema.nullable(),
  signal: z.string().min(1).max(CRASH_REPORT_MAX_LABEL_CHARS).nullable(),
  exception_type: z
    .string()
    .min(1)
    .max(CRASH_REPORT_MAX_LABEL_CHARS)
    .nullable(),
  termination_reason: z
    .string()
    .min(1)
    .max(CRASH_REPORT_MAX_LABEL_CHARS)
    .nullable(),
  summary: z
    .string()
    .min(1)
    .max(CRASH_REPORT_MAX_SUMMARY_CHARS)
    .nullable()
    .describe(
      "The sanitizer's own summary line, bounded and NUL-stripped; it can name a source path from the crashing build.",
    ),
  frames: z.array(crashFrameSchema),
  frames_truncated: z.boolean(),
  text_truncated: z
    .boolean()
    .describe(
      "At least one retained frame field, or a short report label, was clipped to its text budget. The complete report body remains on disk.",
    ),
});

export type CrashReportFacts = z.infer<typeof crashReportFactsSchema>;

/** Frame fields as the parser found them, before the text budget is applied. */
type ParsedFrame = Omit<CrashFrame, "text_truncated">;

/** Facts as the parser found them, before the text budget is applied. */
type ParsedReportFacts = Omit<CrashReportFacts, "frames" | "text_truncated"> & {
  readonly frames: readonly ParsedFrame[];
};

/** Why a report could not be read as a recognized crash report. */
export const CRASH_REPORT_PARSE_REASONS = [
  "empty",
  "unrecognized",
  "no_frames",
  "malformed",
] as const;

export type CrashReportParseReason =
  (typeof CRASH_REPORT_PARSE_REASONS)[number];

/** A report body that is not a recognized crash report. */
export class CrashReportParseFailure extends Error {
  readonly _tag = "CrashReportParseFailure";
  constructor(
    readonly reason: CrashReportParseReason,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
  ) {
    super(message);
    this.name = "CrashReportParseFailure";
  }
}

const sanitizerClassOf = (format: CrashReportFormat): SanitizerClass =>
  SANITIZER_CLASS_OF_FORMAT[format];

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]+/gu;

/** Reduce free text to a bounded token: lowercase alphanumerics and dashes. */
export const crashKindToken = (value: string): string => {
  const token = value
    .toLowerCase()
    .replace(/\([^)]*\)/gu, " ")
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, 64)
    .replace(/-+$/u, "");
  return token === "" ? "unknown" : token;
};

const boundedSummary = (value: string): string | null => {
  const collapsed = value
    .replace(CONTROL_CHARACTERS, " ")
    .replace(/\s+/gu, " ")
    .trim();
  if (collapsed === "") return null;
  return collapsed.length <= CRASH_REPORT_MAX_SUMMARY_CHARS
    ? collapsed
    : `${collapsed.slice(0, CRASH_REPORT_MAX_SUMMARY_CHARS - 1)}…`;
};

const basename = (value: string): string => {
  const parts = value.split(/[\\/]/u);
  return parts[parts.length - 1] ?? value;
};

const moduleGroup = /\s*\(([^()]*\+\s*0x[0-9a-fA-F]+)\)\s*$/u;
const sourceLocation = /\s(\S+?):(\d+)(?::(\d+))?\s*$/u;

const looksLikePath = (value: string): boolean =>
  value.includes("/") || value.includes(".");

interface FrameParts {
  readonly function: string | null;
  readonly module: string | null;
  readonly sourceFile: string | null;
  readonly sourceLine: number | null;
  readonly offset: number | null;
}

/** Split the symbolizer's frame tail into symbol, source location, and module. */
const frameParts = (rawTail: string): FrameParts => {
  let tail = rawTail.trim();
  if (/^in\s+\S/u.test(tail)) tail = tail.replace(/^in\s+/u, "");
  let module: string | null = null;
  let offset: number | null = null;
  const group = moduleGroup.exec(tail);
  if (group !== null) {
    const inner = group[1] ?? "";
    const plus = /\+\s*0x([0-9a-fA-F]+)$/u.exec(inner);
    if (plus !== null) {
      offset = Number.parseInt(plus[1] ?? "0", 16);
      const beforeOffset = inner.slice(0, plus.index).replace(/:[\w-]+$/u, "");
      module = basename(beforeOffset);
    }
    tail = tail.slice(0, group.index);
  }
  let sourceFile: string | null = null;
  let sourceLine: number | null = null;
  const location = sourceLocation.exec(tail);
  if (location !== null && looksLikePath(location[1] ?? "")) {
    sourceFile = location[1] ?? null;
    sourceLine = Number.parseInt(location[2] ?? "0", 10);
    tail = tail.slice(0, location.index);
  }
  let symbol = tail.trim();
  const inlineOffset = /\+\s*0x([0-9a-fA-F]+)$/u.exec(symbol);
  if (inlineOffset !== null) {
    if (offset === null) offset = Number.parseInt(inlineOffset[1] ?? "0", 16);
    symbol = symbol.slice(0, inlineOffset.index).trim();
  }
  return {
    function: symbol === "" ? null : symbol,
    module,
    sourceFile,
    sourceLine,
    offset,
  };
};

const sanitizerFrame = /^\s*#(\d+)\s+(?:0x[0-9a-fA-F]+\s+)?(.*)$/u;

/** Secondary stacks the runtime prints after the crash stack. */
const SECONDARY_STACK =
  /^(?:Allocated by thread|Freed by thread|Previously allocated|Previous (?:write|read|access|atomic|create)|Location is|Shadow bytes|Address 0x)/u;

interface FrameScan {
  readonly frames: readonly ParsedFrame[];
  readonly truncated: boolean;
}

const scanSanitizerFrames = (
  lines: readonly string[],
  startIndex: number,
): FrameScan => {
  const frames: ParsedFrame[] = [];
  let truncated = false;
  for (let index = startIndex; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (SECONDARY_STACK.test(line.trim())) break;
    const match = sanitizerFrame.exec(line);
    if (match === null) {
      if (frames.length > 0 && line.trim() === "") break;
      continue;
    }
    if (frames.length >= CRASH_REPORT_MAX_FRAMES) {
      truncated = true;
      break;
    }
    const parts = frameParts(match[2] ?? "");
    frames.push({
      index: Number.parseInt(match[1] ?? "0", 10),
      function: parts.function,
      module: parts.module,
      source_file: parts.sourceFile,
      source_line: parts.sourceLine,
      offset: parts.offset,
    });
  }
  return { frames, truncated };
};

const firstLineMatching = (
  lines: readonly string[],
  pattern: RegExp,
): string | null => {
  for (const line of lines) {
    const match = pattern.exec(line);
    if (match !== null) return line.trim();
  }
  return null;
};

const crashAccessOf = (line: string | null): CrashAccess | null => {
  if (line === null) return null;
  if (/^(?:WRITE|Write)\b/u.test(line)) return "write";
  if (/^(?:READ|Read)\b/u.test(line)) return "read";
  if (/^(?:READ\/WRITE|Read\/write)\b/u.test(line)) return "read-write";
  return null;
};

const errorLine = (
  lines: readonly string[],
  pattern: RegExp,
): { readonly line: string; readonly index: number } | null => {
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (pattern.test(line)) return { line: line.trim(), index };
  }
  return null;
};

const ASAN_ERROR = /(?:ERROR|SUMMARY): AddressSanitizer: (.*)$/u;
const TSAN_ERROR = /WARNING: ThreadSanitizer: (.*)$/u;
const UBSAN_ERROR =
  /(?:SUMMARY: UndefinedBehaviorSanitizer: |runtime error: )(.*)$/u;
const LSAN_ERROR = /ERROR: LeakSanitizer: (.*)$/u;
const MSAN_ERROR = /WARNING: MemorySanitizer: (.*)$/u;

const asanFacts = (lines: readonly string[]): ParsedReportFacts => {
  const error = errorLine(lines, ASAN_ERROR);
  if (error === null)
    throw new CrashReportParseFailure(
      "malformed",
      "An AddressSanitizer report carried no ERROR or SUMMARY line",
    );
  const errorType = (ASAN_ERROR.exec(error.line)?.[1] ?? "")
    .replace(/\s+(?:on|at)\s+.*$/u, "")
    .trim();
  const accessLine = errorLine(lines, /^\s*(?:READ|WRITE|READ\/WRITE)\b/u);
  const summary = firstLineMatching(lines, /^SUMMARY: AddressSanitizer:/u);
  const scan = scanSanitizerFrames(lines, error.index);
  return {
    format: "asan",
    sanitizer_class: sanitizerClassOf("asan"),
    crash_kind: crashKindToken(errorType === "" ? "unknown" : errorType),
    access: crashAccessOf(accessLine?.line.trim() ?? null),
    signal: null,
    exception_type: null,
    termination_reason: null,
    summary: summary === null ? null : boundedSummary(summary),
    frames: [...scan.frames],
    frames_truncated: scan.truncated,
  };
};

const tsanFacts = (lines: readonly string[]): ParsedReportFacts => {
  const error = errorLine(lines, TSAN_ERROR);
  if (error === null)
    throw new CrashReportParseFailure(
      "malformed",
      "A ThreadSanitizer report carried no WARNING line",
    );
  const errorType = (TSAN_ERROR.exec(error.line)?.[1] ?? "").trim();
  const accessLine = errorLine(
    lines,
    /^\s*(?:Read|Write|Atomic read|Atomic write)\b/u,
  );
  const scan = scanSanitizerFrames(lines, error.index);
  return {
    format: "tsan",
    sanitizer_class: sanitizerClassOf("tsan"),
    crash_kind: crashKindToken(errorType === "" ? "unknown" : errorType),
    access: crashAccessOf(accessLine?.line.trim() ?? null),
    signal: null,
    exception_type: null,
    termination_reason: null,
    summary: boundedSummary(error.line),
    frames: [...scan.frames],
    frames_truncated: scan.truncated,
  };
};

const ubsanFacts = (lines: readonly string[]): ParsedReportFacts => {
  const error = errorLine(lines, UBSAN_ERROR);
  if (error === null)
    throw new CrashReportParseFailure(
      "malformed",
      "An UndefinedBehaviorSanitizer report carried no runtime error line",
    );
  const reported = (UBSAN_ERROR.exec(error.line)?.[1] ?? "").trim();
  const scan = scanSanitizerFrames(lines, error.index);
  const kindSource = reported
    .replace(/\s+\S+:\d+(?::\d+)?(?:\s+in)?\s*$/u, "")
    .replace(/\s+in\s*$/u, "")
    .replace(/:.*$/u, "");
  return {
    format: "ubsan",
    sanitizer_class: sanitizerClassOf("ubsan"),
    crash_kind: crashKindToken(
      kindSource === "" ? "undefined-behavior" : kindSource,
    ),
    access: null,
    signal: null,
    exception_type: null,
    termination_reason: null,
    summary: boundedSummary(error.line),
    frames: [...scan.frames],
    frames_truncated: scan.truncated,
  };
};

const leakFacts = (
  lines: readonly string[],
  format: "lsan" | "msan",
  pattern: RegExp,
): ParsedReportFacts => {
  const error = errorLine(lines, pattern);
  if (error === null)
    throw new CrashReportParseFailure(
      "malformed",
      "A sanitizer report carried no error line",
    );
  const reported = (pattern.exec(error.line)?.[1] ?? "").trim();
  const scan = scanSanitizerFrames(lines, error.index);
  return {
    format,
    sanitizer_class: sanitizerClassOf(format),
    crash_kind: crashKindToken(
      reported === ""
        ? format === "lsan"
          ? "memory-leak"
          : "uninitialized-value"
        : reported,
    ),
    access: null,
    signal: null,
    exception_type: null,
    termination_reason: null,
    summary: boundedSummary(error.line),
    frames: [...scan.frames],
    frames_truncated: scan.truncated,
  };
};

const MACOS_HEADER = /^\s*Thread (\d+)(?: Crashed)?:/u;
const MACOS_FRAME = /^\s*(\d+)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s*(.*)$/u;
const MACOS_FRAME_END =
  /^(?:Binary Images:|Thread \d+:|Application Specific Information:|OS Version:)/u;

const macosFrameParts = (tail: string): FrameParts => {
  const value = tail.trim();
  if (value === "" || value === "???")
    return {
      function: null,
      module: null,
      sourceFile: null,
      sourceLine: null,
      offset: null,
    };
  const offset = /\+\s*(\d+)$/u.exec(value);
  const left = (offset === null ? value : value.slice(0, offset.index)).trim();
  const numeric = /^0x[0-9a-fA-F]+$/u.test(left);
  return {
    function: left === "" || numeric ? null : left,
    module: null,
    sourceFile: null,
    sourceLine: null,
    offset: offset === null ? null : Number.parseInt(offset[1] ?? "0", 10),
  };
};

const macosTextFacts = (lines: readonly string[]): ParsedReportFacts => {
  interface ThreadScan {
    readonly frames: ParsedFrame[];
    truncated: boolean;
  }
  const threads = new Map<number, ThreadScan>();
  let crashedThread: number | null = null;
  let current: number | null = null;
  for (const line of lines) {
    const header = MACOS_HEADER.exec(line);
    if (header !== null) {
      const thread = Number.parseInt(header[1] ?? "0", 10);
      if (threads.has(thread)) {
        current = null;
      } else {
        threads.set(thread, { frames: [], truncated: false });
        current = thread;
      }
      if (/Crashed/u.test(line) && crashedThread === null)
        crashedThread = thread;
      continue;
    }
    if (MACOS_FRAME_END.test(line.trim())) {
      current = null;
      continue;
    }
    if (current === null) continue;
    const frame = MACOS_FRAME.exec(line);
    if (frame === null) continue;
    const scan = threads.get(current);
    if (scan === undefined) continue;
    if (scan.frames.length >= CRASH_REPORT_MAX_FRAMES) {
      scan.truncated = true;
      break;
    }
    const parts = macosFrameParts(frame[4] ?? "");
    scan.frames.push({
      index: Number.parseInt(frame[1] ?? "0", 10),
      function: parts.function,
      module: basename(frame[2] ?? ""),
      source_file: null,
      source_line: null,
      offset: parts.offset,
    });
  }
  const selected =
    (crashedThread === null ? undefined : threads.get(crashedThread)) ??
    [...threads.values()].find((scan) => scan.frames.length > 0);
  const frames = selected?.frames ?? [];
  if (frames.length === 0)
    throw new CrashReportParseFailure(
      "no_frames",
      "A macOS crash report named no thread stack",
      {
        header_lines: lines.length,
      },
    );
  const exception = firstLineMatching(lines, /^Exception Type:/u);
  const termination = firstLineMatching(lines, /^Termination Reason:/u);
  const exceptionType =
    exception === null
      ? null
      : exception.replace(/^Exception Type:\s*/u, "").trim();
  const terminationReason =
    termination === null
      ? null
      : boundedSummary(termination.replace(/^Termination Reason:\s*/u, ""));
  const signalMatch =
    exceptionType === null ? null : /\(([A-Z][A-Z0-9]*)\)/u.exec(exceptionType);
  return {
    format: "macos-text",
    sanitizer_class: sanitizerClassOf("macos-text"),
    crash_kind: crashKindToken(
      exceptionType === null ? "unknown" : exceptionType,
    ),
    access: null,
    signal: signalMatch?.[1] ?? null,
    exception_type:
      exceptionType === null
        ? null
        : exceptionType.replace(/\s*\(.*\)\s*$/u, "").trim() || null,
    termination_reason: terminationReason,
    summary: boundedSummary(
      [exception === null ? null : exception, termination]
        .filter((part) => part !== null)
        .join("; "),
    ),
    frames,
    frames_truncated: selected?.truncated ?? false,
  };
};

interface IpsImage {
  readonly name?: unknown;
  readonly path?: unknown;
}

interface IpsFrame {
  readonly imageIndex?: unknown;
  readonly imageOffset?: unknown;
  readonly symbol?: unknown;
}

interface IpsThread {
  readonly triggered?: unknown;
  readonly frames?: unknown;
}

interface IpsBody {
  readonly exception?: { readonly type?: unknown; readonly signal?: unknown };
  readonly termination?: {
    readonly indicator?: unknown;
    readonly reasons?: unknown;
  };
  readonly faultingThread?: unknown;
  readonly threads?: unknown;
  readonly usedImages?: unknown;
}

const stringOrNull = (value: unknown): string | null =>
  typeof value === "string" && value !== "" ? value : null;

const numberOrNull = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.trunc(value)
    : null;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const parseIpsJson = (
  text: string,
): { readonly body: IpsBody; readonly header: IpsBody } => {
  const direct = ((): unknown => {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return undefined;
    }
  })();
  if (isRecord(direct))
    return { body: direct as IpsBody, header: direct as IpsBody };
  const newline = text.indexOf("\n");
  if (newline < 0)
    throw new CrashReportParseFailure(
      "malformed",
      "A macOS .ips report carried no parseable JSON object",
    );
  let header: unknown;
  try {
    header = JSON.parse(text.slice(0, newline)) as unknown;
  } catch {
    header = undefined;
  }
  let body: unknown;
  try {
    body = JSON.parse(text.slice(newline + 1)) as unknown;
  } catch {
    body = undefined;
  }
  if (!isRecord(body))
    throw new CrashReportParseFailure(
      "malformed",
      "A macOS .ips report body is not a JSON object",
    );
  return {
    body: body as IpsBody,
    header: isRecord(header) ? (header as IpsBody) : (body as IpsBody),
  };
};

const macosIpsFacts = (text: string): ParsedReportFacts => {
  const { body } = parseIpsJson(text);
  const threads = Array.isArray(body.threads)
    ? (body.threads as readonly IpsThread[])
    : [];
  const triggered =
    threads.find((thread) => thread.triggered === true) ?? threads[0];
  const images = Array.isArray(body.usedImages)
    ? (body.usedImages as readonly IpsImage[])
    : [];
  const rawFrames = Array.isArray(triggered?.frames)
    ? (triggered.frames as readonly IpsFrame[])
    : [];
  const frames: ParsedFrame[] = [];
  let truncated = false;
  for (let position = 0; position < rawFrames.length; position += 1) {
    if (frames.length >= CRASH_REPORT_MAX_FRAMES) {
      truncated = true;
      break;
    }
    const frame = rawFrames[position] ?? {};
    const imageIndex = numberOrNull(frame.imageIndex);
    const image = imageIndex === null ? undefined : images[imageIndex];
    frames.push({
      index: position,
      function: stringOrNull(frame.symbol),
      module:
        image === undefined
          ? null
          : (() => {
              const name = stringOrNull(image.name);
              const path = stringOrNull(image.path);
              return name ?? (path === null ? null : basename(path));
            })(),
      source_file: null,
      source_line: null,
      offset: numberOrNull(frame.imageOffset),
    });
  }
  const exceptionType = stringOrNull(body.exception?.type);
  const signal = stringOrNull(body.exception?.signal);
  const termination = stringOrNull(body.termination?.indicator);
  const reasons = body.termination?.reasons;
  const terminationReason =
    Array.isArray(reasons) && typeof reasons[0] === "string"
      ? boundedSummary(reasons[0])
      : null;
  if (frames.length === 0)
    throw new CrashReportParseFailure(
      "no_frames",
      "A macOS .ips crash report carried no frames for the faulting thread",
    );
  return {
    format: "macos-ips",
    sanitizer_class: sanitizerClassOf("macos-ips"),
    crash_kind: crashKindToken(exceptionType ?? termination ?? "unknown"),
    access: null,
    signal,
    exception_type: exceptionType,
    termination_reason: terminationReason,
    summary: boundedSummary(
      [exceptionType, signal, termination]
        .filter((part) => part !== null)
        .join(" "),
    ),
    frames,
    frames_truncated: truncated,
  };
};

const stripSignature = (text: string): string =>
  text.replace(/^\uFEFF/u, "").replace(/\r\n/gu, "\n");

interface ClippedText {
  readonly value: string | null;
  readonly truncated: boolean;
}

/**
 * Clip one text field to its budget, keeping the caller-visible marker.
 *
 * The marker replaces the last retained character, so a clipped value never
 * exceeds the budget the schema advertises and a reader can see that the
 * report carried more.
 */
const clipText = (value: string | null, limit: number): ClippedText => {
  if (value === null) return { value: null, truncated: false };
  if (value.length <= limit) return { value, truncated: false };
  return { value: `${value.slice(0, limit - 1)}…`, truncated: true };
};

const boundFrameText = (
  frame: ParsedFrame,
): {
  readonly frame: CrashFrame;
  readonly truncated: boolean;
} => {
  const function_ = clipText(frame.function, CRASH_REPORT_MAX_FRAME_CHARS);
  const module = clipText(frame.module, CRASH_REPORT_MAX_FRAME_CHARS);
  const sourceFile = clipText(frame.source_file, CRASH_REPORT_MAX_FRAME_CHARS);
  const truncated =
    function_.truncated || module.truncated || sourceFile.truncated;
  return {
    frame: {
      index: frame.index,
      function: function_.value,
      module: module.value,
      source_file: sourceFile.value,
      source_line: frame.source_line,
      offset: frame.offset,
      text_truncated: truncated,
    },
    truncated,
  };
};

/**
 * Apply the report text budget once, after parsing.
 *
 * Every string this function returns is bounded: frame fields to
 * CRASH_REPORT_MAX_FRAME_CHARS, short labels to CRASH_REPORT_MAX_LABEL_CHARS,
 * and the summary to CRASH_REPORT_MAX_SUMMARY_CHARS. `text_truncated` records
 * whether any of them was clipped, so a caller can tell a structural fact from
 * a clipped one instead of receiving report bytes as if they were structure.
 */
const boundReportText = (facts: ParsedReportFacts): CrashReportFacts => {
  const bounded = facts.frames.map(boundFrameText);
  const exceptionType = clipText(
    facts.exception_type,
    CRASH_REPORT_MAX_LABEL_CHARS,
  );
  const signal = clipText(facts.signal, CRASH_REPORT_MAX_LABEL_CHARS);
  const terminationReason = clipText(
    facts.termination_reason,
    CRASH_REPORT_MAX_LABEL_CHARS,
  );
  return {
    ...facts,
    exception_type: exceptionType.value,
    signal: signal.value,
    termination_reason: terminationReason.value,
    frames: bounded.map((entry) => entry.frame),
    text_truncated:
      bounded.some((entry) => entry.truncated) ||
      exceptionType.truncated ||
      signal.truncated ||
      terminationReason.truncated,
  };
};

const detectFormat = (text: string): CrashReportFormat | null => {
  if (/ERROR: AddressSanitizer:|SUMMARY: AddressSanitizer:/u.test(text))
    return "asan";
  if (/WARNING: ThreadSanitizer:|SUMMARY: ThreadSanitizer:/u.test(text))
    return "tsan";
  if (
    /runtime error:|SUMMARY: UndefinedBehaviorSanitizer:|WARNING: UndefinedBehaviorSanitizer:/u.test(
      text,
    )
  )
    return "ubsan";
  if (/ERROR: LeakSanitizer:/u.test(text)) return "lsan";
  if (/WARNING: MemorySanitizer:/u.test(text)) return "msan";
  if (/^\s*\{/u.test(text) && /"bug_type"/u.test(text)) return "macos-ips";
  if (/Exception Type:.*\n|^\s*Thread \d+(?: Crashed)?:/mu.test(text))
    return "macos-text";
  return null;
};

/**
 * Parse one sanitizer or macOS crash report into structural facts.
 *
 * The caller keeps the report body. This function returns only what the
 * report establishes: its family, the runtime's own error type, the retained
 * frames, and the sanitizer's bounded summary line. Nothing is inferred from
 * a report that does not name a crash.
 */
export const parseCrashReport = (body: string): CrashReportFacts => {
  const text = stripSignature(body);
  if (text.trim() === "")
    throw new CrashReportParseFailure(
      "empty",
      "The crash report body is empty",
    );
  const format = detectFormat(text);
  if (format === null)
    throw new CrashReportParseFailure(
      "unrecognized",
      "The supplied text is not a recognized sanitizer or macOS crash report",
      { report_bytes: Buffer.byteLength(text) },
    );
  const lines = text.split("\n");
  const parsed = ((): ParsedReportFacts => {
    switch (format) {
      case "asan":
        return asanFacts(lines);
      case "tsan":
        return tsanFacts(lines);
      case "ubsan":
        return ubsanFacts(lines);
      case "lsan":
        return leakFacts(lines, "lsan", LSAN_ERROR);
      case "msan":
        return leakFacts(lines, "msan", MSAN_ERROR);
      case "macos-ips":
        return macosIpsFacts(text);
      case "macos-text":
        return macosTextFacts(lines);
    }
  })();
  const facts = boundReportText(parsed);
  if (facts.frames.length === 0)
    throw new CrashReportParseFailure(
      "no_frames",
      "The report named its error type but carried no stack frame; REA does not group reports on their kind alone",
      { format: facts.format, crash_kind: facts.crash_kind },
    );
  return facts;
};
