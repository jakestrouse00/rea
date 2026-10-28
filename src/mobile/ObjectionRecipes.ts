import type { ObjectionRecipeId } from "../domain/mobile/mobileToolchain.js";

/** One whitelisted objection recipe: fixed argv and a structure-only row rule. */
export interface ObjectionRecipe {
  readonly id: ObjectionRecipeId;
  readonly summary: string;
  /** The objection `run` sub-command path; never caller-supplied. */
  readonly argv: readonly string[];
  /**
   * Reduce one printed line to a structural row (a name or an identifier), or
   * null when the line carries no structure. Values, payloads, and free text
   * are dropped here rather than filtered later.
   */
  readonly rowOf: (line: string) => string | null;
}

const ANSI = /\u001B\[[0-9;]*[A-Za-z]/gu;

const JAVA_IDENTIFIER = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/u;

const identifierRow = (line: string): string | null => {
  const candidate = line.trim().replace(/,$/u, "");
  return JAVA_IDENTIFIER.test(candidate) ? candidate : null;
};

/** Keep the key of `Key: value` rows: the key names the fact, the value is data. */
const keyRow = (line: string): string | null => {
  const index = line.indexOf(":");
  if (index <= 0) return null;
  const key = line.slice(0, index).trim();
  if (key.length === 0 || key.length > 80) return null;
  if (!/^[\w .()/-]+$/u.test(key)) return null;
  return key;
};

/**
 * The recipes this release accepts. Each is a read-only inventory command
 * whose output is a list of names; nothing here changes device or app state,
 * and free-form objection commands are never assembled from caller input.
 */
export const OBJECTION_RECIPES: readonly ObjectionRecipe[] = [
  {
    id: "app-environment-names",
    summary:
      "Key names of the attached application's environment report; values are dropped",
    argv: ["env"],
    rowOf: keyRow,
  },
  {
    id: "list-loaded-classes",
    summary: "Loaded Java class names in the attached process",
    argv: ["android", "hooking", "list", "classes"],
    rowOf: identifierRow,
  },
  {
    id: "list-activities",
    summary: "Activity class names the package declares",
    argv: ["android", "hooking", "list", "activities"],
    rowOf: identifierRow,
  },
  {
    id: "keystore-aliases",
    summary: "Android Keystore alias names visible to the attached process",
    argv: ["android", "keystore", "list"],
    rowOf: (line) => {
      const candidate = line.trim().replace(/,$/u, "");
      if (candidate.length === 0 || candidate.length > 200) return null;
      if (/\s/u.test(candidate)) return null;
      return candidate;
    },
  },
] as const;

export const findObjectionRecipe = (
  id: ObjectionRecipeId,
): ObjectionRecipe | undefined =>
  OBJECTION_RECIPES.find((recipe) => recipe.id === id);

/**
 * objection's own argv for one recipe. The target selector and `run` keyword
 * are fixed; only the whitelisted recipe path can appear.
 */
export const objectionArguments = (input: {
  readonly recipe: ObjectionRecipe;
  readonly targetKind: "bundle" | "process";
  readonly target: string;
  readonly serial: string | undefined;
}): readonly string[] => [
  input.targetKind === "bundle" ? "-g" : "-n",
  input.target,
  ...(input.serial === undefined ? [] : ["-S", input.serial]),
  "run",
  ...input.recipe.argv,
];

/** Structure-only projection of one objection invocation's printed output. */
export interface ObjectionScrub {
  readonly rows: readonly string[];
  readonly rowCount: number;
  readonly rowsTruncated: boolean;
  readonly droppedLineCount: number;
  readonly unparsedLineCount: number;
}

const BANNER =
  /^(?:Using|Agent|Checking|Waiting|Reading|Attaching|Unable to|Failed to|No )/iu;

/**
 * Reduce printed output to bounded structural rows. A line that names a
 * structure becomes a row; a banner or decoration line is counted as dropped;
 * anything else is counted as unparsed. Duplicate rows collapse so a paged
 * listing does not inflate the inventory.
 */
export const scrubObjectionOutput = (
  recipe: ObjectionRecipe,
  stdout: string,
  maxRows: number,
): ObjectionScrub => {
  const seen = new Set<string>();
  const rows: string[] = [];
  let dropped = 0;
  let unparsed = 0;
  let truncated = false;
  for (const rawLine of stdout.split(/\r?\n/u)) {
    const line = rawLine.replace(ANSI, "").trim();
    if (line.length === 0) continue;
    if (BANNER.test(line)) {
      dropped += 1;
      continue;
    }
    const row = recipe.rowOf(line);
    if (row === null) {
      unparsed += 1;
      continue;
    }
    if (seen.has(row)) continue;
    seen.add(row);
    if (rows.length >= maxRows) {
      truncated = true;
      continue;
    }
    rows.push(row);
  }
  return {
    rows,
    rowCount: seen.size,
    rowsTruncated: truncated,
    droppedLineCount: dropped,
    unparsedLineCount: unparsed,
  };
};
