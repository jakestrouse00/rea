import type {
  JVM_CLASS_KINDS,
  JVM_MEMBER_KINDS,
} from "../domain/jvmdecomp/jvmDecompilation.js";

type ClassKind = (typeof JVM_CLASS_KINDS)[number];
type MemberKind = (typeof JVM_MEMBER_KINDS)[number];

export interface JvmMember {
  readonly kind: MemberKind;
  readonly name: string;
  readonly signature: string;
}

export interface JvmClass {
  readonly binaryName: string;
  readonly packageName: string | null;
  readonly name: string;
  readonly kind: ClassKind;
  readonly members: readonly JvmMember[];
}

export interface JvmSourceInventory {
  readonly classes: readonly JvmClass[];
  readonly unparsedLines: number;
}

const PACKAGE_DECLARATION =
  /^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;/u;
const TYPE_DECLARATION =
  /^\s*(?:(?:public|protected|private|static|final|abstract|sealed|non-sealed|strictfp)\s+)*(class|interface|enum|record|@interface)\s+([A-Za-z_$][\w$]*)/u;
const COMMENT = /^\s*(?:\/\/|\/\*|\*)/u;

const kindOf = (token: string): ClassKind =>
  token === "@interface" ? "annotation" : (token as ClassKind);

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

const memberKindOf = (line: string, typeName: string): MemberKind | null => {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed === "{" || trimmed === "}" || trimmed === "};")
    return null;
  if (COMMENT.test(trimmed)) return null;
  if (/\(/u.test(trimmed)) {
    const name = /([A-Za-z_$][\w$]*)\s*\(/u.exec(trimmed)?.[1];
    if (name === undefined) return null;
    return name === typeName ? "constructor" : "method";
  }
  if (/;\s*$/u.test(trimmed)) return "field";
  if (/^[A-Za-z_$][\w$]*\s*,?$/u.test(trimmed)) return "field";
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
      return /([A-Za-z_$][\w$]*)\s*\(/u.exec(trimmed)?.[1] ?? null;
    case "field": {
      const withoutInitializer = trimmed.split("=")[0] ?? trimmed;
      return (
        /([A-Za-z_$][\w$]*)\s*[,;]?\s*$/u.exec(
          withoutInitializer.trim(),
        )?.[1] ?? null
      );
    }
    case "unknown":
      return null;
  }
};

/** Parse one recovered `.java` source into its public declaration structure. */
export const parseJavaSource = (
  source: string,
  maxMembers: number,
): JvmSourceInventory => {
  const classes: JvmClass[] = [];
  const memberCounts = new Map<JvmClass, JvmMember[]>();
  const typeStack: { readonly type: JvmClass; readonly bodyDepth: number }[] =
    [];
  let packageName: string | null = null;
  let depth = 0;
  let unparsedLines = 0;
  let pendingType: { readonly type: JvmClass } | null = null;

  for (const rawLine of source.split(/\r?\n/u)) {
    const line = stripComments(rawLine);
    const trimmed = line.trim();
    if (trimmed === "") continue;

    if (pendingType !== null && trimmed.startsWith("{")) {
      typeStack.push({ type: pendingType.type, bodyDepth: depth + 1 });
      memberCounts.set(pendingType.type, []);
      pendingType = null;
    }

    const packageDeclaration = PACKAGE_DECLARATION.exec(line);
    if (packageDeclaration !== null) {
      packageName = packageDeclaration[1] ?? null;
      continue;
    }

    const declaration = TYPE_DECLARATION.exec(line);
    if (declaration !== null) {
      const name = declaration[2]!;
      const type: JvmClass = {
        binaryName: packageName === null ? name : `${packageName}.${name}`,
        packageName,
        name,
        kind: kindOf(declaration[1]!),
        members: [],
      };
      classes.push(type);
      if (line.includes("{")) {
        typeStack.push({ type, bodyDepth: depth + 1 });
        memberCounts.set(type, []);
      } else pendingType = { type };
    } else {
      const innermost = typeStack.at(-1);
      if (innermost !== undefined && depth === innermost.bodyDepth) {
        const kind = memberKindOf(line, innermost.type.name);
        const name =
          kind === null ? null : memberNameOf(line, kind, innermost.type.name);
        const signature = cleanSignature(line);
        if (kind !== null && name !== null && signature !== "") {
          const members = memberCounts.get(innermost.type) ?? [];
          if (
            members.length < maxMembers &&
            !members.some((existing) => existing.signature === signature)
          )
            members.push({ kind, name, signature });
          else if (members.length >= maxMembers) unparsedLines += 1;
          memberCounts.set(innermost.type, members);
        } else if (kind !== null) unparsedLines += 1;
      }
    }

    depth += braceDelta(line);
    while (typeStack.length > 0 && typeStack.at(-1)!.bodyDepth > depth)
      typeStack.pop();
  }

  return {
    classes: classes.map((type) => ({
      ...type,
      members: memberCounts.get(type) ?? [],
    })),
    unparsedLines,
  };
};
