import { createHash } from "node:crypto";
import { open, rename, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import {
  mitmRulePhase,
  type MitmRuleAction,
  type MitmRuleMatch,
} from "../domain/mitm/mitmRule.js";
import type { MitmRulePhase } from "../domain/mitm/mitmLimits.js";

/** One armed rule as REA keeps it and mirrors it into the control file. */
export interface MitmArmedRule {
  readonly ruleId: string;
  readonly match: MitmRuleMatch;
  readonly action: MitmRuleAction;
  readonly expiresAtMs: number;
}

/** Wire shape the addon reads; it carries the values a rewrite needs. */
interface MitmControlDocument {
  readonly version: 1;
  readonly revision: number;
  readonly rules: readonly {
    readonly rule_id: string;
    readonly phase: MitmRulePhase;
    readonly match: {
      readonly origins: readonly string[];
      readonly path_prefixes: readonly string[];
      readonly methods: readonly string[];
    };
    readonly action: unknown;
    readonly expires_at: number;
  }[];
}

const actionDocument = (action: MitmRuleAction): unknown =>
  action.kind === "request"
    ? {
        kind: "request",
        set_headers: action.setHeaders.map(({ name, value }) => [name, value]),
        remove_headers: action.removeHeaders,
        set_query: action.setQuery.map(({ name, value }) => [name, value]),
        remove_query: action.removeQuery,
        ...(action.bodyBase64 === undefined
          ? {}
          : { body_base64: action.bodyBase64 }),
      }
    : {
        kind: "response",
        set_headers: action.setHeaders.map(({ name, value }) => [name, value]),
        remove_headers: action.removeHeaders,
        ...(action.status === undefined ? {} : { status: action.status }),
        ...(action.bodyBase64 === undefined
          ? {}
          : { body_base64: action.bodyBase64 }),
      };

/** Serialize one control revision; the addon applies it on its next flow. */
export const mitmControlDocument = (
  revision: number,
  rules: Iterable<MitmArmedRule>,
): string =>
  JSON.stringify({
    version: 1,
    revision,
    rules: [...rules].map((rule) => ({
      rule_id: rule.ruleId,
      phase: mitmRulePhase(rule.action),
      match: {
        origins: rule.match.origins,
        path_prefixes: rule.match.pathPrefixes,
        methods: rule.match.methods,
      },
      action: actionDocument(rule.action),
      expires_at: rule.expiresAtMs,
    })),
  } satisfies MitmControlDocument);

/** Replace the control file atomically so the addon never reads half a rule. */
export const writeMitmControlFile = async (
  path: string,
  revision: number,
  content: string,
): Promise<{ readonly revision: number; readonly sha256: string }> => {
  const temporary = join(
    dirname(path),
    `.${basename(path)}.${String(process.pid)}.tmp`,
  );
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(content, "utf8");
    await handle.sync().catch(() => undefined);
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, path);
  } catch (cause: unknown) {
    await unlink(temporary).catch(() => undefined);
    throw cause;
  }
  return {
    revision,
    sha256: createHash("sha256").update(content).digest("hex"),
  };
};
