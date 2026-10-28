import { describe, expect, it } from "vitest";

import {
  browserFetchInputSchema,
  browserRequestRuleSetInputSchema,
} from "./browserMutation.js";
import { BROWSER_MUTATION_LIMITS } from "./browserMutationLimits.js";
import { REPLAY_LIMITS } from "./replay/replayLimits.js";

const fetchInput = (body: unknown) => ({
  cdp_endpoint: "http://127.0.0.1:9250",
  allowed_origins: ["https://app.example.test"],
  target_id: "allowed-page",
  method: "POST",
  url: "https://app.example.test/api/session",
  headers: [],
  timeout_ms: 5_000,
  overwrite: false,
  body,
});

const issuesFor = (body: unknown) => {
  const parsed = browserFetchInputSchema.safeParse(fetchInput(body));
  return parsed.success ? [] : parsed.error.issues;
};

describe("browser_fetch request body bounds", () => {
  it("admits a body at the shared request-body bound", () => {
    const text = "a".repeat(REPLAY_LIMITS.maxRequestBodyBytes);
    expect(issuesFor({ kind: "text", text })).toEqual([]);
  });

  it("refuses a UTF-8 body past the bound before any dispatch", () => {
    const text = "a".repeat(REPLAY_LIMITS.maxRequestBodyBytes + 1);
    expect(issuesFor({ kind: "text", text })).toMatchObject([
      {
        code: "custom",
        path: ["body", "text"],
        message: `One request body is limited to ${String(REPLAY_LIMITS.maxRequestBodyBytes)} bytes.`,
      },
    ]);
  });

  it("refuses decoded base64 bytes past the bound", () => {
    const base64 = Buffer.alloc(REPLAY_LIMITS.maxRequestBodyBytes + 1).toString(
      "base64",
    );
    expect(issuesFor({ kind: "base64", base64 })).toMatchObject([
      { code: "custom", path: ["body", "base64"] },
    ]);
  });

  it("refuses a non-canonical base64 body", () => {
    expect(
      issuesFor({ kind: "base64", base64: "%%%not-base64%%%" }),
    ).toMatchObject([{ code: "custom", path: ["body", "base64"] }]);
  });
});

describe("browser_request_rule_set replacement body bounds", () => {
  it("admits a padded rule body at the exact byte bound", () => {
    const base64 = Buffer.alloc(
      BROWSER_MUTATION_LIMITS.maxRuleBodyBytes,
    ).toString("base64");
    const parsed = browserRequestRuleSetInputSchema.safeParse({
      cdp_endpoint: "http://127.0.0.1:9250",
      allowed_origins: ["https://app.example.test"],
      target_id: "allowed-page",
      match: { methods: ["POST"] },
      action: { kind: "modify", body_base64: base64 },
    });
    expect(parsed.success).toBe(true);
  });

  it("keeps the rule body bound below the request-body bound", () => {
    const base64 = Buffer.alloc(
      BROWSER_MUTATION_LIMITS.maxRuleBodyBytes + 1,
    ).toString("base64");
    const parsed = browserRequestRuleSetInputSchema.safeParse({
      cdp_endpoint: "http://127.0.0.1:9250",
      allowed_origins: ["https://app.example.test"],
      target_id: "allowed-page",
      match: { methods: ["POST"] },
      action: { kind: "modify", body_base64: base64 },
    });
    expect(parsed.success).toBe(false);
  });
});
