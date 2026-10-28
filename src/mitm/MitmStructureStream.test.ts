import { describe, expect, it } from "vitest";

import { parseMitmStreamEvent } from "../domain/mitm/mitmStream.js";

const flow = {
  type: "flow",
  sequence: 1,
  at: "2026-01-01T00:00:00.000Z",
  duration_ms: 3,
  request: {
    method: "GET",
    origin: "https://api.example.test",
    path_template: "/v1/items",
    header_names: ["accept"],
    parameters: [{ name: "page", location: "query", type: "integer" }],
    content_type_class: "absent",
    body_bytes: 0,
    body_hold: null,
  },
  response: {
    status: 200,
    header_names: ["content-type"],
    content_type_class: "json",
    body_bytes: 4,
    body_hold: {
      path: "/cases/capture/bodies/1.res.bin",
      bytes: 4,
      sha256: "a".repeat(64),
    },
    shape: {
      kind: "array",
      items: 1,
      item: {
        kind: "object",
        keys: [{ name: "id", type: "integer" }],
        truncated: false,
      },
      truncated: false,
    },
  },
  entry: null,
};

describe("mitm structure stream parser", () => {
  it("parses a flow frame and preserves structure only", () => {
    const parsed = parseMitmStreamEvent(JSON.stringify(flow));
    expect(parsed.kind).toBe("event");
    if (parsed.kind !== "event") return;
    expect(parsed.event.type).toBe("flow");
    expect(JSON.stringify(parsed.event)).not.toContain("page=");
  });

  it("parses rule matches, notices, and errors", () => {
    for (const event of [
      {
        type: "rule_match",
        rule_id: "0b4f5d4c-1a52-4f7f-9a0e-9f9a1a0b3c4d",
        phase: "response",
        method: "GET",
        origin: "https://api.example.test",
        path_template: "/v1/items",
        status_before: 200,
        status_after: 418,
        headers_changed: 0,
        query_changed: 0,
        body_replaced: false,
      },
      { type: "notice", reason: "control-unreadable", message: "bad file" },
      { type: "error", reason: "response-hook", message: "boom" },
    ]) {
      const parsed = parseMitmStreamEvent(JSON.stringify(event));
      expect(parsed.kind, JSON.stringify(event)).toBe("event");
    }
  });

  it("keeps malformed and unknown frames distinguishable", () => {
    expect(parseMitmStreamEvent("not json").kind).toBe("invalid");
    expect(parseMitmStreamEvent("[]").kind).toBe("invalid");
    expect(parseMitmStreamEvent('{"value":1}').kind).toBe("invalid");
    expect(parseMitmStreamEvent('{"type":"mystery"}').kind).toBe(
      "unknown-type",
    );
    expect(
      parseMitmStreamEvent(JSON.stringify({ ...flow, type: "ready" })).kind,
    ).toBe("unknown-type");
  });

  it("rejects frames that carry a value instead of a name", () => {
    const parsed = parseMitmStreamEvent(
      JSON.stringify({
        ...flow,
        request: {
          ...flow.request,
          parameters: [{ name: "page", value: "2" }],
        },
      }),
    );
    expect(parsed.kind).toBe("invalid");
  });

  it("rejects a body hold outside the declared digest shape", () => {
    const parsed = parseMitmStreamEvent(
      JSON.stringify({
        ...flow,
        response: {
          ...flow.response,
          body_hold: { path: "/cases/x.bin", bytes: 4, sha256: "nope" },
        },
      }),
    );
    expect(parsed.kind).toBe("invalid");
  });
});
