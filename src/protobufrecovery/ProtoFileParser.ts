export interface ProtoField {
  readonly name: string;
  readonly number: number | null;
  readonly type: string;
  readonly label: "optional" | "required" | "repeated" | "singular" | "map";
  readonly map: boolean;
}

export interface ProtoMessage {
  readonly name: string;
  readonly fields: readonly ProtoField[];
  readonly nestedMessageCount: number;
}

export interface ProtoEnumValue {
  readonly name: string;
  readonly number: number | null;
}

export interface ProtoEnum {
  readonly name: string;
  readonly values: readonly ProtoEnumValue[];
}

export interface ParsedProto {
  readonly package: string | null;
  readonly messages: readonly ProtoMessage[];
  readonly enums: readonly ProtoEnum[];
  readonly serviceCount: number;
  readonly unparsedLines: number;
}

interface Context {
  readonly kind: "message" | "enum" | "service" | "other";
  readonly name: string;
  readonly bodyDepth: number;
  readonly message?: ProtoMessage | undefined;
  readonly enum?: ProtoEnum | undefined;
}

const PACKAGE = /^\s*package\s+([A-Za-z_][\w.]*)\s*;/u;
const MESSAGE = /^\s*message\s+([A-Za-z_]\w*)\s*\{?/u;
const ENUM = /^\s*enum\s+([A-Za-z_]\w*)\s*\{?/u;
const SERVICE = /^\s*service\s+([A-Za-z_]\w*)\s*\{?/u;
const ONEOF = /^\s*oneof\s+([A-Za-z_]\w*)\s*\{?/u;
const MAP_FIELD =
  /^\s*(optional|required|repeated)?\s*map\s*<\s*([^,>]+)\s*,\s*([^>]+)\s*>\s+([A-Za-z_]\w*)\s*=\s*(\d+)/u;
const FIELD =
  /^\s*(optional|required|repeated)?\s*([A-Za-z_.][\w.]*)\s+([A-Za-z_]\w*)\s*=\s*(\d+)/u;
const ENUM_VALUE = /^\s*([A-Za-z_]\w*)\s*=\s*(-?\d+)/u;
const NON_DECLARATION =
  /^\s*(?:option|reserved|extensions|syntax|import|package|public|weak)\b/u;

const stripComments = (line: string): string => {
  const withoutBlock = line.replaceAll(/\/\*.*?\*\//gu, " ");
  const start = withoutBlock.indexOf("//");
  return start === -1 ? withoutBlock : withoutBlock.slice(0, start);
};

const braceDelta = (line: string): number => {
  let delta = 0;
  for (const character of line) {
    if (character === "{") delta += 1;
    else if (character === "}") delta -= 1;
  }
  return delta;
};

const fieldLabel = (
  modifier: string | undefined,
  map: boolean,
): ProtoField["label"] => {
  if (map) return "map";
  if (
    modifier === "optional" ||
    modifier === "required" ||
    modifier === "repeated"
  )
    return modifier;
  return "singular";
};

/**
 * Parse one recovered `.proto` file into packages, messages, fields, enums, and
 * service counts. Field options and default values are never read, so they
 * cannot reach Evidence.
 */
export const parseProtoFile = (source: string): ParsedProto => {
  const messages: ProtoMessage[] = [];
  const enums: ProtoEnum[] = [];
  const contexts: Context[] = [];
  const messageFields = new Map<ProtoMessage, ProtoField[]>();
  const messageNested = new Map<ProtoMessage, number>();
  const enumValues = new Map<ProtoEnum, ProtoEnumValue[]>();
  let packageName: string | null = null;
  let depth = 0;
  let serviceCount = 0;
  let unparsedLines = 0;
  let pending: Omit<Context, "bodyDepth"> | null = null;

  const open = (context: Omit<Context, "bodyDepth">) => {
    contexts.push({ ...context, bodyDepth: depth + 1 });
  };

  for (const rawLine of source.split(/\r?\n/u)) {
    const line = stripComments(rawLine);
    const trimmed = line.trim();
    if (trimmed === "") continue;

    if (pending !== null && trimmed.startsWith("{")) {
      open(pending);
      pending = null;
      depth += braceDelta(line);
      continue;
    }

    const packageMatch = PACKAGE.exec(line);
    if (packageMatch !== null) {
      packageName = packageMatch[1] ?? null;
      continue;
    }

    const messageMatch = MESSAGE.exec(line);
    if (messageMatch !== null) {
      const name = messageMatch[1]!;
      const message: ProtoMessage = {
        name,
        fields: [],
        nestedMessageCount: 0,
      };
      messages.push(message);
      messageFields.set(message, []);
      messageNested.set(message, 0);
      const parent = contexts.at(-1);
      if (parent?.message !== undefined)
        messageNested.set(
          parent.message,
          (messageNested.get(parent.message) ?? 0) + 1,
        );
      if (line.includes("{")) {
        open({ kind: "message", name, message });
        depth += braceDelta(line);
      } else pending = { kind: "message", name, message };
      continue;
    }

    const enumMatch = ENUM.exec(line);
    if (enumMatch !== null) {
      const name = enumMatch[1]!;
      const enumeration: ProtoEnum = { name, values: [] };
      enums.push(enumeration);
      enumValues.set(enumeration, []);
      if (line.includes("{")) {
        open({ kind: "enum", name, enum: enumeration });
        depth += braceDelta(line);
      } else pending = { kind: "enum", name, enum: enumeration };
      continue;
    }

    const serviceMatch = SERVICE.exec(line);
    if (serviceMatch !== null) {
      serviceCount += 1;
      if (line.includes("{")) open({ kind: "service", name: serviceMatch[1]! });
      else pending = { kind: "service", name: serviceMatch[1]! };
      if (line.includes("{")) depth += braceDelta(line);
      continue;
    }

    const oneofMatch = ONEOF.exec(line);
    if (oneofMatch !== null) {
      if (line.includes("{")) open({ kind: "other", name: oneofMatch[1]! });
      else pending = { kind: "other", name: oneofMatch[1]! };
      if (line.includes("{")) depth += braceDelta(line);
      continue;
    }

    const innermost = contexts.at(-1);
    if (innermost?.kind === "enum" && depth === innermost.bodyDepth) {
      const value = ENUM_VALUE.exec(line);
      if (value !== null) {
        enumValues.get(innermost.enum!)?.push({
          name: value[1]!,
          number: Number.parseInt(value[2]!, 10),
        });
      } else if (!NON_DECLARATION.test(trimmed)) unparsedLines += 1;
    } else if (
      innermost?.kind === "message" &&
      depth >= innermost.bodyDepth &&
      depth <= innermost.bodyDepth + 1
    ) {
      const mapField = MAP_FIELD.exec(line);
      const field = FIELD.exec(line);
      const fields = messageFields.get(innermost.message!);
      if (mapField !== null) {
        fields?.push({
          name: mapField[4]!,
          number: Number.parseInt(mapField[5]!, 10),
          type: `map<${mapField[2]!.trim()},${mapField[3]!.trim()}>`,
          label: "map",
          map: true,
        });
      } else if (field !== null) {
        const type = field[2]!;
        if (type === "option" || type === "reserved") {
          // Options and reserved ranges are not fields.
        } else {
          fields?.push({
            name: field[3]!,
            number: Number.parseInt(field[4]!, 10),
            type,
            label: fieldLabel(field[1], false),
            map: false,
          });
        }
      } else if (!NON_DECLARATION.test(trimmed)) unparsedLines += 1;
    } else if (contexts.some(({ kind }) => kind === "service") && depth > 0) {
      // RPC declarations are counted through serviceCount only.
    }

    depth += braceDelta(line);
    while (contexts.length > 0 && depth < contexts.at(-1)!.bodyDepth)
      contexts.pop();
  }

  return {
    package: packageName,
    messages: messages.map((message) => ({
      ...message,
      fields: messageFields.get(message) ?? [],
      nestedMessageCount: messageNested.get(message) ?? 0,
    })),
    enums: enums.map((enumeration) => ({
      ...enumeration,
      values: enumValues.get(enumeration) ?? [],
    })),
    serviceCount,
    unparsedLines,
  };
};
