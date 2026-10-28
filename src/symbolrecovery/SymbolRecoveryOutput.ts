import { parseJsonObject } from "../domain/jsonShape.js";

export interface RecoveredFunction {
  readonly name: string;
  readonly entry: string | null;
  readonly size: number | null;
}

export interface GoSymbolInventory {
  readonly goVersion: string | null;
  readonly arch: string | null;
  readonly os: string | null;
  readonly modulePath: string | null;
  readonly functions: readonly RecoveredFunction[];
  readonly unparsedEntries: number;
}

export interface BreakpadModule {
  readonly os: string | null;
  readonly arch: string | null;
  readonly id: string | null;
  readonly name: string | null;
}

export interface BreakpadFunction {
  readonly name: string;
  readonly address: string | null;
  readonly size: number | null;
  readonly parameterSize: number | null;
}

export interface BreakpadInventory {
  readonly module: BreakpadModule | null;
  readonly functions: readonly BreakpadFunction[];
  readonly publicCount: number;
  readonly fileCount: number;
  readonly unparsedEntries: number;
  readonly truncated: boolean;
}

const nonEmpty = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value.trim() : null;

const asObject = (value: unknown): Record<string, unknown> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

const asArray = (value: unknown): readonly unknown[] =>
  Array.isArray(value) ? value : [];

const firstString = (...values: readonly unknown[]): string | null => {
  for (const value of values) {
    const text = nonEmpty(value);
    if (text !== null) return text;
  }
  return null;
};

const integerOf = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0
    ? value
    : null;

const addressOf = (value: unknown): string | null => {
  const numeric = integerOf(value);
  return numeric === null ? null : `0x${numeric.toString(16)}`;
};

/** Parse GoReSym's JSON document into a bounded function inventory. */
export const parseGoReSymJson = (stdout: string): GoSymbolInventory | null => {
  const document = parseJsonObject(stdout);
  if (document === null) return null;
  const module =
    asObject(document.ModuleInfo) ?? asObject(document.module_info);
  const functions = [
    ...asArray(document.UserFunctions),
    ...asArray(document.StdFunctions),
    ...asArray(document.user_functions),
    ...asArray(document.std_functions),
  ];
  if (
    document.Version === undefined &&
    document.version === undefined &&
    functions.length === 0
  )
    return null;
  let unparsedEntries = 0;
  const recovered: RecoveredFunction[] = [];
  for (const entry of functions) {
    const record = asObject(entry);
    if (record === null) {
      unparsedEntries += 1;
      continue;
    }
    const name = firstString(
      record.FullName,
      record.full_name,
      record.Name,
      record.name,
      record.PackageName,
      record.package_name,
    );
    if (name === null) {
      unparsedEntries += 1;
      continue;
    }
    const start =
      integerOf(record.Start) ??
      integerOf(record.start) ??
      integerOf(record.Entry) ??
      integerOf(record.entry);
    const end = integerOf(record.End) ?? integerOf(record.end);
    recovered.push({
      name,
      entry: addressOf(start),
      size:
        integerOf(record.Size) ??
        integerOf(record.size) ??
        (start !== null && end !== null && end >= start ? end - start : null),
    });
  }
  return {
    goVersion: firstString(
      document.Version,
      document.version,
      asObject(document.Meta)?.Version,
    ),
    arch: firstString(document.Arch, document.arch, document.GOARCH),
    os: firstString(document.OS, document.os, document.GOOS),
    modulePath: firstString(
      module?.Path,
      module?.path,
      asObject(module?.Main)?.Path,
      module?.name,
    ),
    functions: recovered,
    unparsedEntries,
  };
};

/** Parse Breakpad `MODULE`/`FILE`/`FUNC`/`PUBLIC` text into counts and rows. */
export const parseBreakpadSymbols = (
  stdout: string,
  maxFunctions: number,
): BreakpadInventory => {
  let module: BreakpadModule | null = null;
  const functions: BreakpadFunction[] = [];
  let publicCount = 0;
  let fileCount = 0;
  let unparsedEntries = 0;
  let truncated = false;
  for (const line of stdout.split(/\r?\n/u)) {
    if (line.trim() === "") continue;
    const parts = line.split(/\s+/u);
    switch (parts[0]) {
      case "MODULE":
        module ??= {
          os: nonEmpty(parts[1]),
          arch: nonEmpty(parts[2]),
          id: nonEmpty(parts[3]),
          name: nonEmpty(parts.slice(4).join(" ")),
        };
        break;
      case "FILE":
        fileCount += 1;
        break;
      case "PUBLIC":
        publicCount += 1;
        break;
      case "FUNC": {
        const offset = parts[1] === "m" ? 1 : 0;
        const address = nonEmpty(parts[1 + offset]);
        const sizeText = nonEmpty(parts[2 + offset]);
        const parameterText = nonEmpty(parts[3 + offset]);
        const name = nonEmpty(parts.slice(4 + offset).join(" "));
        if (name === null) {
          unparsedEntries += 1;
          break;
        }
        const size = sizeText === null ? null : Number.parseInt(sizeText, 16);
        const parameterSize =
          parameterText === null ? null : Number.parseInt(parameterText, 16);
        if (functions.length < maxFunctions)
          functions.push({
            name,
            address,
            size: Number.isFinite(size) ? size : null,
            parameterSize: Number.isFinite(parameterSize)
              ? (parameterSize as number)
              : null,
          });
        else {
          unparsedEntries += 1;
          truncated = true;
        }
        break;
      }
      default:
        unparsedEntries += 1;
    }
  }
  return {
    module,
    functions,
    publicCount,
    fileCount,
    unparsedEntries,
    truncated,
  };
};

/** Pair each caller-supplied name with its demangled line, if the tool changed it. */
export const parseDemangledNames = (
  names: readonly string[],
  stdout: string,
): readonly {
  readonly mangled: string;
  readonly demangled: string | null;
}[] => {
  const lines = stdout.split(/\r?\n/u);
  if (lines.at(-1) === "") lines.pop();
  return names.map((mangled, index) => {
    const echoed = lines[index]?.trim();
    return {
      mangled,
      demangled:
        echoed === undefined || echoed === "" || echoed === mangled.trim()
          ? null
          : echoed,
    };
  });
};
