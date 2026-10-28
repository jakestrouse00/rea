/** Tolerant readers for the ipsw JSON dialects this lane consumes. */
type JsonObject = Readonly<Record<string, unknown>>;

export type IpswValueKind =
  | "string"
  | "integer"
  | "boolean"
  | "array"
  | "dictionary"
  | "data"
  | "unknown";

export interface IpswArchiveInfo {
  readonly product: string | null;
  readonly version: string | null;
  readonly build: string | null;
  readonly buildTrain: string | null;
  readonly deviceIdentifiers: readonly string[];
  readonly devicesReported: boolean;
  readonly partitionsReported: boolean;
  readonly partitions: readonly {
    readonly name: string;
    readonly bytes: number | null;
    readonly sha256: string | null;
  }[];
  readonly unparsedEntries: number;
}

export interface IpswDscManifest {
  readonly architecture: string | null;
  readonly images: readonly {
    readonly name: string;
    readonly path: string | null;
    readonly address: string | null;
    readonly bytes: number | null;
  }[];
  readonly unparsedEntries: number;
}

export interface IpswClassEntry {
  readonly name: string;
  readonly superclass: string | null;
  readonly protocols: readonly string[];
  readonly methods: readonly {
    readonly name: string;
    readonly kind: "instance" | "class" | "unknown";
    readonly returnType: string | null;
    readonly parameterTypes: readonly string[];
  }[];
  readonly ivars: readonly {
    readonly name: string;
    readonly type: string | null;
    readonly offset: number | null;
  }[];
}

export interface IpswClassTable {
  readonly classes: readonly IpswClassEntry[];
  readonly unparsedEntries: number;
}

export interface IpswCrashSymbolication {
  readonly threads: readonly {
    readonly id: number | null;
    readonly name: string | null;
    readonly crashed: boolean;
    readonly frames: readonly {
      readonly index: number;
      readonly image: string | null;
      readonly symbol: string | null;
      readonly address: string | null;
      readonly offset: string | null;
      readonly sourceFile: string | null;
      readonly sourceLine: number | null;
    }[];
  }[];
  readonly unparsedEntries: number;
}

export interface IpswMachoSummary {
  readonly architecture: string | null;
  readonly fileType: string | null;
  readonly entitlements: readonly {
    readonly key: string;
    readonly valueKind: IpswValueKind;
  }[];
  readonly loadCommands: readonly {
    readonly command: string;
    readonly size: number | null;
    readonly offset: number | null;
  }[];
  readonly unparsedEntries: number;
}

/** Parse one JSON document; undefined means the output was not JSON at all. */
export const parseIpswJson = (stdout: string): unknown => {
  const trimmed = stdout.trim();
  if (trimmed === "") return undefined;
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return undefined;
  }
};

const asObject = (value: unknown): JsonObject | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : null;

const asArray = (value: unknown): readonly unknown[] =>
  Array.isArray(value) ? value : [];

const textOf = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

const integerOf = (value: unknown): number | null => {
  if (typeof value === "number")
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
};

const booleanOf = (value: unknown): boolean | null =>
  typeof value === "boolean" ? value : null;

/** Render one address as 0x-prefixed lowercase hexadecimal text. */
export const hexAddressOf = (value: unknown): string | null => {
  if (typeof value === "number")
    return Number.isSafeInteger(value) && value >= 0
      ? `0x${value.toString(16)}`
      : null;
  const text = textOf(value);
  if (text === null) return null;
  if (/^0[xX][0-9a-fA-F]+$/u.test(text))
    return `0x${text.slice(2).toLowerCase()}`;
  if (/^\d+$/u.test(text)) return `0x${BigInt(text).toString(16)}`;
  return null;
};

const digestOf = (value: unknown): string | null => {
  const text = textOf(value);
  return text !== null && /^[a-fA-F0-9]{64}$/u.test(text)
    ? text.toLowerCase()
    : null;
};

const baseNameOf = (path: string): string => path.split("/").at(-1) ?? path;

/** Read one archive inventory document from `ipsw info --json`. */
export const parseIpswInfoOutput = (value: unknown): IpswArchiveInfo | null => {
  const root = asObject(value);
  if (root === null) return null;
  let unparsedEntries = 0;
  const deviceRows = asArray(root.devices);
  const devicesReported = Array.isArray(root.devices);
  const deviceIdentifiers: string[] = [];
  for (const device of deviceRows) {
    const text = typeof device === "string" ? textOf(device) : null;
    const record = asObject(device);
    const identifier =
      text ??
      (record === null
        ? null
        : (textOf(record.identifier) ??
          textOf(record.product) ??
          textOf(record.name) ??
          textOf(record.device)));
    if (identifier === null) unparsedEntries += 1;
    else deviceIdentifiers.push(identifier);
  }
  const partitionRows = asArray(root.files).length
    ? asArray(root.files)
    : asArray(root.partitions);
  const partitionsReported =
    Array.isArray(root.files) || Array.isArray(root.partitions);
  const partitions: IpswArchiveInfo["partitions"][number][] = [];
  for (const row of partitionRows) {
    const record = asObject(row);
    if (record === null) {
      unparsedEntries += 1;
      continue;
    }
    const path =
      textOf(record.path) ?? textOf(record.name) ?? textOf(record.filename);
    if (path === null) {
      unparsedEntries += 1;
      continue;
    }
    partitions.push({
      name: baseNameOf(path),
      bytes: integerOf(record.size) ?? integerOf(record.bytes),
      sha256: digestOf(record.digest) ?? digestOf(record.sha256),
    });
  }
  return {
    product:
      textOf(root.product) ??
      textOf(root.productType) ??
      textOf(root.identifier),
    version: textOf(root.version),
    build: textOf(root.build),
    buildTrain: textOf(root.buildtrain) ?? textOf(root.buildTrain),
    deviceIdentifiers,
    devicesReported,
    partitionsReported,
    partitions,
    unparsedEntries,
  };
};

/** Read one dyld shared-cache manifest from `ipsw dyld info --json`. */
export const parseDscManifestOutput = (
  value: unknown,
): IpswDscManifest | null => {
  const root = asObject(value);
  if (root === null) return null;
  const rows = Array.isArray(root.images)
    ? root.images
    : Array.isArray(root.dylibs)
      ? root.dylibs
      : null;
  if (rows === null) return null;
  let unparsedEntries = 0;
  const images: IpswDscManifest["images"][number][] = [];
  for (const row of rows) {
    if (typeof row === "string") {
      const path = textOf(row);
      if (path === null) {
        unparsedEntries += 1;
        continue;
      }
      images.push({
        name: baseNameOf(path),
        path,
        address: null,
        bytes: null,
      });
      continue;
    }
    const record = asObject(row);
    if (record === null) {
      unparsedEntries += 1;
      continue;
    }
    const path = textOf(record.path);
    const name =
      textOf(record.name) ?? (path === null ? null : baseNameOf(path));
    if (name === null) {
      unparsedEntries += 1;
      continue;
    }
    images.push({
      name,
      path,
      address: hexAddressOf(record.address) ?? hexAddressOf(record.base),
      bytes: integerOf(record.size) ?? integerOf(record.bytes),
    });
  }
  return {
    architecture:
      textOf(root.arch) ?? textOf(root.architecture) ?? textOf(root.platform),
    images,
    unparsedEntries,
  };
};

const methodKindOf = (
  record: JsonObject,
  fallback: "instance" | "class",
): "instance" | "class" | "unknown" => {
  const declared =
    textOf(record.kind) ?? textOf(record.type) ?? textOf(record.methodType);
  if (declared !== null) {
    const normalized = declared.toLowerCase();
    if (normalized.includes("class")) return "class";
    if (normalized.includes("instance")) return "instance";
  }
  const isClass = booleanOf(record.is_class) ?? booleanOf(record.isClass);
  if (isClass === true) return "class";
  if (isClass === false) return "instance";
  return fallback;
};

const parameterTypesOf = (record: JsonObject): string[] => {
  const rows =
    asArray(record.parameters).length > 0
      ? asArray(record.parameters)
      : asArray(record.parameterTypes).length > 0
        ? asArray(record.parameterTypes)
        : asArray(record.arguments);
  const types: string[] = [];
  for (const row of rows) {
    const text = typeof row === "string" ? row : textOf(asObject(row)?.type);
    if (text !== null) types.push(text);
  }
  return types;
};

const methodOf = (
  value: unknown,
  fallback: "instance" | "class",
): IpswClassEntry["methods"][number] | null => {
  if (typeof value === "string") {
    const name = textOf(value);
    return name === null
      ? null
      : {
          name,
          kind: fallback,
          returnType: null,
          parameterTypes: [],
        };
  }
  const record = asObject(value);
  if (record === null) return null;
  const name =
    textOf(record.name) ?? textOf(record.selector) ?? textOf(record.signature);
  if (name === null) return null;
  const returnType =
    textOf(record.return_type) ??
    textOf(record.returnType) ??
    textOf(record.return);
  return {
    name,
    kind: methodKindOf(record, fallback),
    returnType,
    parameterTypes: parameterTypesOf(record),
  };
};

const ivarOf = (value: unknown): IpswClassEntry["ivars"][number] | null => {
  if (typeof value === "string") {
    const name = textOf(value);
    return name === null ? null : { name, type: null, offset: null };
  }
  const record = asObject(value);
  if (record === null) return null;
  const name =
    textOf(record.name) ?? textOf(record.ivar) ?? textOf(record.ivarName);
  if (name === null) return null;
  return {
    name,
    type: textOf(record.type) ?? textOf(record.typeEncoding),
    offset: integerOf(record.offset),
  };
};

const protocolNamesOf = (value: unknown): string[] => {
  const names: string[] = [];
  for (const row of asArray(value)) {
    const name =
      typeof row === "string"
        ? textOf(row)
        : (textOf(asObject(row)?.name) ?? null);
    if (name !== null) names.push(name);
  }
  return names;
};

/**
 * Read Objective-C class tables or Swift type tables. Both dialects normalize
 * into one class table; entries this reader cannot name are counted, never
 * guessed.
 */
export const parseClassMetadataOutput = (
  value: unknown,
): IpswClassTable | null => {
  const root = asObject(value);
  const rows = Array.isArray(value)
    ? value
    : root === null
      ? null
      : Array.isArray(root.classes)
        ? root.classes
        : Array.isArray(root.types)
          ? root.types
          : null;
  if (rows === null) return null;
  let unparsedEntries = 0;
  const classes: IpswClassEntry[] = [];
  for (const row of rows) {
    const record = asObject(row);
    if (record === null) {
      unparsedEntries += 1;
      continue;
    }
    const name =
      textOf(record.name) ??
      textOf(record.className) ??
      textOf(record.typeName);
    if (name === null) {
      unparsedEntries += 1;
      continue;
    }
    const methods: IpswClassEntry["methods"][number][] = [];
    for (const method of asArray(record.instanceMethods)) {
      const parsed = methodOf(method, "instance");
      if (parsed === null) unparsedEntries += 1;
      else methods.push(parsed);
    }
    for (const method of asArray(record.classMethods)) {
      const parsed = methodOf(method, "class");
      if (parsed === null) unparsedEntries += 1;
      else methods.push(parsed);
    }
    for (const method of asArray(record.methods)) {
      const parsed = methodOf(method, "instance");
      if (parsed === null) unparsedEntries += 1;
      else methods.push(parsed);
    }
    const ivars: IpswClassEntry["ivars"][number][] = [];
    const ivarRows = asArray(record.ivars).length
      ? asArray(record.ivars)
      : asArray(record.instanceVariables);
    for (const ivar of ivarRows) {
      const parsed = ivarOf(ivar);
      if (parsed === null) unparsedEntries += 1;
      else ivars.push(parsed);
    }
    for (const field of asArray(record.fields)) {
      const parsed = ivarOf(field);
      if (parsed === null) unparsedEntries += 1;
      else ivars.push(parsed);
    }
    classes.push({
      name,
      superclass:
        textOf(record.superclass) ??
        textOf(record.superClass) ??
        textOf(record.superclass_name),
      protocols: [
        ...protocolNamesOf(record.protocols),
        ...protocolNamesOf(record.superProtocols),
      ],
      methods,
      ivars,
    });
  }
  return { classes, unparsedEntries };
};

/** Read one symbolicated crash document from `ipsw symbolicate --json`. */
export const parseCrashSymbolicationOutput = (
  value: unknown,
): IpswCrashSymbolication | null => {
  const root = asObject(value);
  if (root === null) return null;
  const nested = asObject(root.crash);
  const rows = Array.isArray(root.threads)
    ? root.threads
    : Array.isArray(nested?.threads)
      ? nested.threads
      : null;
  if (rows === null) return null;
  let unparsedEntries = 0;
  const threads: IpswCrashSymbolication["threads"][number][] = [];
  for (const row of rows) {
    const record = asObject(row);
    if (record === null) {
      unparsedEntries += 1;
      continue;
    }
    const frameRows = asArray(record.frames).length
      ? asArray(record.frames)
      : asArray(record.stack);
    const frames: IpswCrashSymbolication["threads"][number]["frames"][number][] =
      [];
    for (const [position, frame] of frameRows.entries()) {
      const frameRecord = asObject(frame);
      if (frameRecord === null) {
        unparsedEntries += 1;
        continue;
      }
      const address =
        hexAddressOf(frameRecord.address) ??
        hexAddressOf(frameRecord.pc) ??
        hexAddressOf(frameRecord.instruction);
      frames.push({
        index: integerOf(frameRecord.index) ?? position,
        image:
          textOf(frameRecord.image) ??
          textOf(frameRecord.imageName) ??
          textOf(frameRecord.image_name),
        symbol:
          textOf(frameRecord.symbol) ??
          textOf(frameRecord.symbolName) ??
          textOf(frameRecord.symbol_name),
        address,
        offset:
          hexAddressOf(frameRecord.offset) ??
          hexAddressOf(frameRecord.imageOffset),
        sourceFile:
          textOf(frameRecord.source_file) ??
          textOf(frameRecord.sourceFile) ??
          textOf(frameRecord.file),
        sourceLine:
          integerOf(frameRecord.source_line) ??
          integerOf(frameRecord.sourceLine) ??
          integerOf(frameRecord.line),
      });
    }
    threads.push({
      id: integerOf(record.id) ?? integerOf(record.thread),
      name: textOf(record.name) ?? textOf(record.threadName),
      crashed:
        booleanOf(record.crashed) ??
        booleanOf(record.triggered) ??
        booleanOf(record.faulting) ??
        false,
      frames,
    });
  }
  return { threads, unparsedEntries };
};

const VALUE_KINDS: Readonly<Record<string, IpswValueKind>> = {
  string: "string",
  str: "string",
  integer: "integer",
  int: "integer",
  number: "integer",
  boolean: "boolean",
  bool: "boolean",
  array: "array",
  dictionary: "dictionary",
  dict: "dictionary",
  object: "dictionary",
  data: "data",
};

const valueKindOf = (value: unknown): IpswValueKind => {
  if (typeof value === "string") return "string";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number")
    return Number.isInteger(value) ? "integer" : "unknown";
  if (Array.isArray(value)) return "array";
  if (typeof value === "object" && value !== null) return "dictionary";
  return "unknown";
};

const normalizedValueKind = (value: unknown): IpswValueKind => {
  const declared = textOf(value);
  return declared === null
    ? "unknown"
    : (VALUE_KINDS[declared.toLowerCase()] ?? "unknown");
};

/**
 * Read code-signing entitlements and load commands from
 * `ipsw macho info --json --entitlements`. Entitlement values never enter the
 * result: only the key and a value-kind label are retained.
 */
export const parseMachoEntitlementsOutput = (
  value: unknown,
): IpswMachoSummary | null => {
  const root = asObject(value);
  if (root === null) return null;
  if (!("entitlements" in root) && !("load_commands" in root)) return null;
  let unparsedEntries = 0;
  const entitlements: IpswMachoSummary["entitlements"][number][] = [];
  const entitlementRecord = asObject(root.entitlements);
  if (entitlementRecord !== null) {
    for (const [key, entry] of Object.entries(entitlementRecord))
      entitlements.push({ key, valueKind: valueKindOf(entry) });
  } else {
    for (const row of asArray(root.entitlements)) {
      const record = asObject(row);
      if (record === null) {
        unparsedEntries += 1;
        continue;
      }
      const key = textOf(record.key) ?? textOf(record.name);
      if (key === null) {
        unparsedEntries += 1;
        continue;
      }
      const declared = normalizedValueKind(
        record.value_kind ?? record.valueKind ?? record.type,
      );
      entitlements.push({
        key,
        valueKind:
          declared === "unknown" && "value" in record
            ? valueKindOf(record.value)
            : declared,
      });
    }
  }
  const loadCommands: IpswMachoSummary["loadCommands"][number][] = [];
  const commandRows = asArray(root.load_commands).length
    ? asArray(root.load_commands)
    : asArray(root.loadCommands).length
      ? asArray(root.loadCommands)
      : asArray(root.commands);
  for (const row of commandRows) {
    if (typeof row === "string") {
      const command = textOf(row);
      if (command === null) unparsedEntries += 1;
      else loadCommands.push({ command, size: null, offset: null });
      continue;
    }
    const record = asObject(row);
    if (record === null) {
      unparsedEntries += 1;
      continue;
    }
    const command =
      textOf(record.command) ?? textOf(record.cmd) ?? textOf(record.name);
    if (command === null) {
      unparsedEntries += 1;
      continue;
    }
    loadCommands.push({
      command,
      size: integerOf(record.size) ?? integerOf(record.cmdsize),
      offset:
        integerOf(record.offset) ??
        integerOf(record.file_offset) ??
        integerOf(record.fileOffset),
    });
  }
  return {
    architecture:
      textOf(root.arch) ?? textOf(root.architecture) ?? textOf(root.cpu),
    fileType:
      textOf(root.type) ?? textOf(root.fileType) ?? textOf(root.file_type),
    entitlements,
    loadCommands,
    unparsedEntries,
  };
};
