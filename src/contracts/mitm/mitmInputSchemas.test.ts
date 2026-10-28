import { describe, expect, it } from "vitest";

import { MITM_LIMITS } from "../../domain/mitm/mitmLimits.js";
import {
  proxyRuleSetInputSchema,
  proxyReplaySendInputSchema,
} from "./mitmInputSchemas.js";

const SESSION = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

const rule = (
  action: Record<string, unknown>,
  match: Record<string, unknown> = { path_prefixes: ["/v1"] },
) =>
  proxyRuleSetInputSchema.safeParse({
    session_id: SESSION,
    match,
    action,
  });

const issuePaths = (parsed: ReturnType<typeof rule>): unknown =>
  parsed.success ? [] : parsed.error.issues.map(({ path }) => path);

describe("mitm rule header and query fields", () => {
  it("admits a token header name and an ordinary value", () => {
    expect(
      rule({
        kind: "request",
        set_headers: [{ name: "x-probe", value: "1" }],
        set_query: [{ name: "filter[type]", value: "a b" }],
      }).success,
    ).toBe(true);
  });

  it("refuses a header name that is not a token", () => {
    for (const name of ["x bad", "x:y", "x\r\nInjected", "x\u0000y"]) {
      const parsed = rule({
        kind: "request",
        set_headers: [{ name, value: "1" }],
      });
      expect(parsed.success, name).toBe(false);
    }
    expect(
      issuePaths(
        rule({
          kind: "request",
          set_headers: [{ name: "x\r\nInjected", value: "1" }],
        }),
      ),
    ).toEqual([["action", "set_headers", 0, "name"]]);
  });

  it("refuses CR, LF, or NUL in a header value", () => {
    for (const value of ["1\r\nX-Injected: yes", "1\n2", "a\u0000b", "a\rb"]) {
      expect(
        rule({
          kind: "request",
          set_headers: [{ name: "x-probe", value }],
        }).success,
        JSON.stringify(value),
      ).toBe(false);
    }
  });

  it("refuses line breaks in query names and values", () => {
    expect(
      rule({
        kind: "request",
        set_query: [{ name: "a\nb", value: "1" }],
      }).success,
    ).toBe(false);
    expect(
      rule({
        kind: "request",
        set_query: [{ name: "a", value: "1\r\n2" }],
      }).success,
    ).toBe(false);
    expect(
      rule({ kind: "response", set_headers: [], remove_headers: ["a b"] })
        .success,
    ).toBe(false);
    expect(rule({ kind: "request", remove_query: ["a\nb"] }).success).toBe(
      false,
    );
  });

  it("refuses CR, LF, or NUL in a response header value", () => {
    expect(
      rule({
        kind: "response",
        set_headers: [{ name: "x-answer", value: "1\r\n\r\n<html>" }],
      }).success,
    ).toBe(false);
  });
});

describe("mitm rule body bound", () => {
  it("admits a padded body at the exact byte bound", () => {
    const base64 = Buffer.alloc(MITM_LIMITS.maxRuleBodyBytes).toString(
      "base64",
    );
    expect(rule({ kind: "request", body_base64: base64 }).success).toBe(true);
  });

  it("refuses one byte past the bound", () => {
    const base64 = Buffer.alloc(MITM_LIMITS.maxRuleBodyBytes + 1).toString(
      "base64",
    );
    expect(rule({ kind: "request", body_base64: base64 }).success).toBe(false);
  });
});

describe("proxy_replay_send header fields", () => {
  it("keeps token and line-break validation at the replay composition owner", () => {
    const send = (headers: { name: string; value: string }[]) =>
      proxyReplaySendInputSchema.safeParse({
        session_id: SESSION,
        sequence: 1,
        set_headers: headers,
      }).success;
    expect(send([{ name: "x-probe", value: "1" }])).toBe(true);
    // The advertised schema bounds length; composeReplayRequest owns the token
    // and line-break rules for every replay lane, and proxy_replay_send keeps
    // its headers on that path.
    expect(send([{ name: "x bad", value: "1" }])).toBe(true);
  });
});
