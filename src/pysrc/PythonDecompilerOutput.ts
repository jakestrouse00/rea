export interface PythonFunction {
  readonly name: string;
  readonly qualifiedName: string;
  readonly lineStart: number;
  readonly lineEnd: number;
  readonly parameterCount: number;
}

export interface PythonInventory {
  readonly functions: readonly PythonFunction[];
  readonly classes: readonly string[];
  readonly imports: readonly string[];
  readonly unparsedLines: number;
}

const CLASS_DECLARATION = /^(\s*)class\s+([A-Za-z_]\w*)/u;
const FUNCTION_DECLARATION = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/u;
const IMPORT_DECLARATION = /^\s*import\s+(.+)$/u;
const FROM_IMPORT_DECLARATION = /^\s*from\s+([A-Za-z_][\w.]*)\s+import\b/u;
const DECORATOR = /^\s*@/u;
const COMMENT = /^\s*#/u;

const indentOf = (line: string): number => {
  const match = /^[ \t]*/u.exec(line)?.[0] ?? "";
  let width = 0;
  for (const character of match) width += character === "\t" ? 4 : 1;
  return width;
};

/** Count parameters in the text after the opening parenthesis. */
const parameterCountOf = (text: string): number => {
  let depth = 0;
  let current = "";
  const parameters: string[] = [];
  for (const character of text) {
    if (character === "(" || character === "[" || character === "{") {
      depth += 1;
      current += character;
    } else if (character === ")" || character === "]" || character === "}") {
      depth -= 1;
      current += character;
    } else if (character === "," && depth === 0) {
      parameters.push(current);
      current = "";
    } else {
      current += character;
    }
  }
  if (current.trim() !== "") parameters.push(current);
  return parameters.filter((parameter) => {
    const name = parameter.split("=")[0]?.trim() ?? "";
    return name !== "" && name !== "self" && name !== "cls";
  }).length;
};

const moduleOfImport = (statement: string): readonly string[] =>
  statement
    .split(",")
    .map((entry) => entry.split(/\s+as\s+/u)[0]?.trim() ?? "")
    .filter((entry) => entry !== "");

/**
 * Parse recovered Python source into declarations, line ranges, and import
 * module names. Source text is never republished.
 */
export const parsePythonSource = (stdout: string): PythonInventory => {
  const lines = stdout.split(/\r?\n/u);
  const functions: PythonFunction[] = [];
  const classes: string[] = [];
  const imports: string[] = [];
  const scopeStack: { readonly name: string; readonly indent: number }[] = [];
  let unparsedLines = 0;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.trim() === "" || COMMENT.test(line) || DECORATOR.test(line))
      continue;
    const indent = indentOf(line);

    const fromImport = FROM_IMPORT_DECLARATION.exec(line);
    if (fromImport !== null) {
      if (imports.length < 2_000) imports.push(fromImport[1]!);
      continue;
    }
    const importStatement = IMPORT_DECLARATION.exec(line);
    if (importStatement !== null) {
      for (const module of moduleOfImport(importStatement[1]!))
        if (imports.length < 2_000) imports.push(module);
      continue;
    }

    const classDeclaration = CLASS_DECLARATION.exec(line);
    if (classDeclaration !== null) {
      while (scopeStack.length > 0 && scopeStack.at(-1)!.indent >= indent)
        scopeStack.pop();
      const name = classDeclaration[2]!;
      scopeStack.push({ name, indent });
      if (classes.length < 2_000) classes.push(name);
      continue;
    }

    const declaration = FUNCTION_DECLARATION.exec(line);
    if (declaration === null) continue;
    while (scopeStack.length > 0 && scopeStack.at(-1)!.indent >= indent)
      scopeStack.pop();
    const name = declaration[2]!;
    const textAfter = line.slice(declaration[0].length);
    const parameterText = textAfter.split(")")[0] ?? "";
    const lineStart = index + 1;
    let lineEnd = lineStart;
    for (let next = index + 1; next < lines.length; next += 1) {
      const candidate = lines[next] ?? "";
      if (candidate.trim() === "") continue;
      if (!COMMENT.test(candidate) && !DECORATOR.test(candidate)) {
        if (indentOf(candidate) <= indent) break;
      }
      lineEnd = next + 1;
    }
    const qualifiedName =
      scopeStack.length === 0
        ? name
        : `${scopeStack.map(({ name: scope }) => scope).join(".")}.${name}`;
    scopeStack.push({ name, indent });
    functions.push({
      name,
      qualifiedName,
      lineStart,
      lineEnd,
      parameterCount: parameterCountOf(parameterText),
    });
  }

  for (const line of lines)
    if (/^\s*(?:def|class)\s+$/u.test(line)) unparsedLines += 1;

  return { functions, classes, imports, unparsedLines };
};
