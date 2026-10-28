import { createHash, randomUUID } from "node:crypto";
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

/** Filesystem owners the writer uses; a test can make one attempt fail. */
export interface MitmControlFileOperations {
  readonly open: typeof open;
  readonly rename: typeof rename;
  readonly unlink: typeof unlink;
}

const FILE_OPERATIONS: MitmControlFileOperations = { open, rename, unlink };

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

/**
 * Replace the control file atomically so the addon never reads half a rule.
 *
 * Each attempt owns a unique temporary path and removes it on every failure
 * path, so a full disk, an I/O error, or a failed rename never leaves a file
 * that makes the next attempt fail with EEXIST.
 */
export const writeMitmControlFile = async (
  path: string,
  revision: number,
  content: string,
  operations: MitmControlFileOperations = FILE_OPERATIONS,
): Promise<{ readonly revision: number; readonly sha256: string }> => {
  const temporary = join(
    dirname(path),
    `.${basename(path)}.${String(process.pid)}.${randomUUID()}.tmp`,
  );
  const handle = await operations.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(content, "utf8");
    await handle.sync().catch(() => undefined);
  } catch (cause: unknown) {
    await handle.close().catch(() => undefined);
    await operations.unlink(temporary).catch(() => undefined);
    throw cause;
  }
  await handle.close().catch(() => undefined);
  try {
    await operations.rename(temporary, path);
  } catch (cause: unknown) {
    await operations.unlink(temporary).catch(() => undefined);
    throw cause;
  }
  return {
    revision,
    sha256: createHash("sha256").update(content).digest("hex"),
  };
};
