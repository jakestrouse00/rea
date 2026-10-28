import type {
  DOTNET_MEMBER_KINDS,
  DOTNET_TYPE_KINDS,
} from "../domain/manageddecomp/dotnetDecompilation.js";

type TypeKind = (typeof DOTNET_TYPE_KINDS)[number];
type MemberKind = (typeof DOTNET_MEMBER_KINDS)[number];

export interface DotnetMember {
  readonly kind: MemberKind;
  readonly name: string;
  readonly signature: string;
}

export interface DotnetType {
  readonly namespace: string | null;
  readonly name: string;
  readonly kind: TypeKind;
  readonly baseType: string | null;
  readonly members: readonly DotnetMember[];
}

export interface DotnetInventory {
  readonly types: readonly DotnetType[];
  readonly unparsedLines: number;
}

const TYPE_DECLARATION =
  /(?:^|\s)(?:public|internal|private|protected|static|sealed|abstract|partial|readonly|ref|unsafe|new|file)\s+(?:(?:public|internal|private|protected|static|sealed|abstract|partial|readonly|ref|unsafe|new|file)\s+)*(class|struct|interface|enum|record|delegate)\s+([A-Za-z_][\w`]*)/u;
const NAMESPACE_DECLARATION = /(?:^|\s)namespace\s+([A-Za-z_][\w.]*)/u;
const ATTRIBUTE_LINE = /^\s*\[/u;
const ACCESS_MODIFIER =
  /^\s*(?:public|internal|private|protected|static|sealed|abstract|partial|readonly|virtual|override|async|extern|unsafe|new|required|const|fixed|implicit|explicit)\b/u;

const stripComments = (line: string): string => {
  const withoutBlock = line.replaceAll(/\/\*.*?\*\//gu, " ");
  const commentStart = withoutBlock.indexOf("//");
  return commentStart === -1
    ? withoutBlock
    : withoutBlock.slice(0, commentStart);
};

const braceDelta = (line: string): number => {
  let delta = 0;
  for (const character of line) {
    if (character === "{") delta += 1;
    else if (character === "}") delta -= 1;
  }
  return delta;
};

const cleanSignature = (line: string): string =>
  line
    .trim()
    .replace(/\{.*$/u, "")
    .replace(/=>.*$/u, "")
    .replace(/[;,]\s*$/u, "")
    .replace(/\s+/gu, " ")
    .trim();

const baseTypeOf = (line: string): string | null => {
  const index = line.indexOf(":");
  if (index === -1) return null;
  const segment = line
    .slice(index + 1)
    .split(/[,{]/u)[0]
    ?.trim();
  return segment === undefined || segment === "" ? null : segment;
};

const memberKindOf = (line: string, typeName: string): MemberKind | null => {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed === "{" || trimmed === "}" || trimmed === "};")
    return null;
  if (ATTRIBUTE_LINE.test(trimmed)) return null;
  if (/\bevent\s+/u.test(trimmed)) return "event";
  if (/\boperator\s*[^\w\s]/u.test(trimmed)) return "operator";
  if (/\(/u.test(trimmed)) {
    const name = /([A-Za-z_]\w*)\s*(?:<[^()]*>)?\s*\(/u.exec(trimmed)?.[1];
    return name === typeName ? "constructor" : "method";
  }
  if (/\{\s*(?:get|set|init)\b|=>/u.test(trimmed)) return "property";
  if (/;\s*$/u.test(trimmed)) return "field";
  if (/^[A-Za-z_]\w*\s*,?$/u.test(trimmed)) return "field";
  return null;
};

const memberNameOf = (
  line: string,
  kind: MemberKind,
  typeName: string,
): string | null => {
  const trimmed = line.trim();
  switch (kind) {
    case "constructor":
      return typeName;
    case "method":
    case "operator":
      return /([A-Za-z_]\w*)\s*(?:<[^()]*>)?\s*\(/u.exec(trimmed)?.[1] ?? null;
    case "property":
      return /([A-Za-z_]\w*)\s*(?:\{|=>)/u.exec(trimmed)?.[1] ?? null;
    case "event":
      return (
        /\bevent\s+[\w<>.,?[\]]+\s+([A-Za-z_]\w*)/u.exec(trimmed)?.[1] ?? null
      );
    case "field": {
      const withoutInitializer = trimmed.split("=")[0] ?? trimmed;
      return (
        /([A-Za-z_]\w*)\s*[,;]?\s*$/u.exec(withoutInitializer.trim())?.[1] ??
        null
      );
    }
    case "unknown":
      return null;
  }
};

/**
 * Parse ilspycmd's decompiled C# into a structural type/member inventory.
 *
 * The text is never republished. Declaration scanning is deliberately shallow:
 * braces and declaration lines define the structure, and lines that do not
 * resolve to a recognized member are counted rather than guessed.
 */
export const parseDotnetDeclarations = (
  stdout: string,
  maxTypes: number,
): DotnetInventory => {
  const types: DotnetType[] = [];
  const memberCounts = new Map<DotnetType, DotnetMember[]>();
  const typeStack: { readonly type: DotnetType; readonly bodyDepth: number }[] =
    [];
  let namespaceScope: { readonly name: string; readonly depth: number } | null =
    null;
  let fileScopedNamespace: string | null = null;
  let depth = 0;
  let unparsedLines = 0;
  let pendingType: {
    readonly type: DotnetType;
    readonly declDepth: number;
  } | null = null;

  const lines = stdout.split(/\r?\n/u);
  for (const rawLine of lines) {
    const line = stripComments(rawLine);
    const trimmed = line.trim();
    if (trimmed === "") continue;

    if (pendingType !== null && trimmed.startsWith("{")) {
      typeStack.push({ type: pendingType.type, bodyDepth: depth + 1 });
      memberCounts.set(pendingType.type, []);
      pendingType = null;
    }

    const namespace = NAMESPACE_DECLARATION.exec(line);
    if (namespace !== null) {
      const name = namespace[1] ?? null;
      if (line.includes("{")) namespaceScope = { name: name ?? "", depth };
      else fileScopedNamespace = name;
    }
    const currentNamespace = namespaceScope?.name ?? fileScopedNamespace;

    const declaration = TYPE_DECLARATION.exec(line);
    if (declaration !== null) {
      const kind = declaration[1] as TypeKind;
      const name = declaration[2]!;
      if (types.length < maxTypes) {
        const type: DotnetType = {
          namespace: currentNamespace,
          name,
          kind,
          baseType: baseTypeOf(line),
          members: [],
        };
        types.push(type);
        if (line.includes("{")) {
          const bodyDepth = depth + 1;
          typeStack.push({ type, bodyDepth });
          memberCounts.set(type, []);
        } else if (!trimmed.endsWith(";")) {
          pendingType = { type, declDepth: depth };
        }
      }
    } else {
      const innermost = typeStack.at(-1);
      if (
        innermost !== undefined &&
        depth === innermost.bodyDepth &&
        !trimmed.startsWith("{") &&
        !trimmed.startsWith("}") &&
        !ATTRIBUTE_LINE.test(trimmed) &&
        !ACCESS_MODIFIER.test(trimmed) &&
        !/^(?:namespace|using)\b/u.test(trimmed)
      )
        unparsedLines += 1;
      if (innermost !== undefined && depth === innermost.bodyDepth) {
        const kind = memberKindOf(line, innermost.type.name);
        const name =
          kind === null ? null : memberNameOf(line, kind, innermost.type.name);
        const signature = cleanSignature(line);
        if (kind !== null && name !== null && signature !== "") {
          const members = memberCounts.get(innermost.type) ?? [];
          if (!members.some((existing) => existing.signature === signature))
            members.push({ kind, name, signature });
          memberCounts.set(innermost.type, members);
        } else if (kind !== null) unparsedLines += 1;
      }
    }

    depth += braceDelta(line);
    while (typeStack.length > 0 && typeStack.at(-1)!.bodyDepth > depth)
      typeStack.pop();
    if (namespaceScope !== null && namespaceScope.depth >= depth)
      namespaceScope = null;
  }

  return {
    types: types.map((type) => ({
      ...type,
      members: memberCounts.get(type) ?? [],
    })),
    unparsedLines,
  };
};
