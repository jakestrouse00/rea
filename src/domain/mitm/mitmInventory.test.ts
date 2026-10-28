import { describe, expect, it } from "vitest";

import { MitmInventory } from "./mitmInventory.js";
import { MITM_LIMITS } from "./mitmLimits.js";
import type { MitmFlowEvent } from "./mitmStream.js";

const flow = (
  sequence: number,
  overrides: Partial<MitmFlowEvent> = {},
): MitmFlowEvent => ({
  type: "flow",
  sequence,
  at: `2026-01-01T00:00:0${String(sequence)}.000Z`,
  duration_ms: 1,
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
    body_hold: null,
    shape: {
      kind: "object",
      keys: [{ name: "id", type: "string" }],
      truncated: false,
    },
  },
  entry: null,
  ...overrides,
});

const repeated = (): MitmInventory => {
  const inventory = new MitmInventory();
  inventory.applyFlow(flow(1));
  inventory.applyFlow(
    flow(2, {
      request: {
        ...flow(2).request,
        header_names: ["accept", "x-trace"],
        parameters: [
          { name: "page", location: "query", type: "integer" },
          { name: "page", location: "query", type: "string" },
        ],
      },
      response: {
        status: 404,
        header_names: ["content-type", "x-request-id"],
        content_type_class: "json",
        body_bytes: 4,
        body_hold: { path: "/tmp/body.bin", bytes: 4, sha256: "0".repeat(64) },
        shape: { kind: "scalar", type: "string" },
      },
    }),
  );
  inventory.applyFlow(
    flow(3, {
      request: { ...flow(3).request, method: "POST" },
      response: null,
    }),
  );
  return inventory;
};

describe("mitm inventory totals", () => {
  it("counts flows, endpoints, bodies, and unanswered requests", () => {
    expect(repeated().snapshot().totals).toEqual({
      flows: 3,
      endpoints: 2,
      endpoints_omitted: 0,
      facts_omitted: 0,
      requests_without_response: 1,
      bodies_held: 1,
      body_bytes_held: 4,
    });
  });

  it("orders endpoints by origin, path template, then method", () => {
    const inventory = new MitmInventory();
    for (const [origin, method, path] of [
      ["https://b.example.test", "GET", "/a"],
      ["https://a.example.test", "POST", "/z"],
      ["https://a.example.test", "GET", "/z"],
      ["https://a.example.test", "GET", "/a"],
    ] as const)
      inventory.applyFlow(
        flow(1, {
          request: { ...flow(1).request, origin, method, path_template: path },
        }),
      );
    expect(
      inventory
        .snapshot()
        .endpoints.map(({ origin, method, path_template }) => [
          origin,
          method,
          path_template,
        ]),
    ).toEqual([
      ["https://a.example.test", "GET", "/a"],
      ["https://a.example.test", "GET", "/z"],
      ["https://a.example.test", "POST", "/z"],
      ["https://b.example.test", "GET", "/a"],
    ]);
  });
});

describe("mitm inventory endpoint facts", () => {
  it("merges occurrences, statuses, header names, types, and shape variants", () => {
    const [get, post] = repeated().snapshot().endpoints;
    expect(get).toMatchObject({
      origin: "https://api.example.test",
      method: "GET",
      path_template: "/v1/items",
      occurrences: 2,
      first_at: "2026-01-01T00:00:01.000Z",
      last_at: "2026-01-01T00:00:02.000Z",
      shape_variants: 1,
    });
    expect(get?.status_histogram).toEqual([
      { status: 200, status_class: "success", count: 1 },
      { status: 404, status_class: "client_error", count: 1 },
    ]);
    expect(get?.request_header_names).toEqual(["accept", "x-trace"]);
    expect(get?.response_header_names).toEqual([
      "content-type",
      "x-request-id",
    ]);
    expect(get?.parameters).toEqual([
      { name: "page", location: "query", types: ["integer", "string"] },
    ]);
    expect(post?.method).toBe("POST");
    expect(post?.status_histogram).toEqual([]);
  });

  it("retains a bounded nested shape with its truncation marker", () => {
    const shape = {
      kind: "array" as const,
      items: 1,
      item: {
        kind: "array" as const,
        items: 1,
        item: { kind: "truncated" as const, deeper: true as const },
        truncated: true,
      },
      truncated: false,
    };
    const inventory = new MitmInventory();
    inventory.applyFlow(
      flow(1, {
        response: { ...flow(1).response!, shape },
      }),
    );
    expect(inventory.snapshot().endpoints[0]?.response_shape).toEqual(shape);
  });
});

describe("mitm inventory bounds", () => {
  it("reports omitted endpoints instead of dropping them silently", () => {
    const inventory = new MitmInventory();
    for (let index = 0; index <= MITM_LIMITS.maxEndpoints; index += 1)
      inventory.applyFlow(
        flow(index + 1, {
          request: {
            ...flow(index + 1).request,
            path_template: `/v1/items/${String(index)}`,
          },
        }),
      );
    const snapshot = inventory.snapshot();
    expect(snapshot.totals.endpoints).toBe(MITM_LIMITS.maxEndpoints);
    expect(snapshot.totals.endpoints_omitted).toBe(1);
    expect(snapshot.totals.flows).toBe(MITM_LIMITS.maxEndpoints + 1);
  });

  it("bounds parameter rows, types, statuses, and header names", () => {
    const inventory = new MitmInventory();
    inventory.applyFlow(
      flow(1, {
        request: {
          ...flow(1).request,
          header_names: Array.from(
            { length: MITM_LIMITS.maxHeaderNames + 1 },
            (_, index) => `h-${String(index)}`,
          ),
          parameters: Array.from(
            { length: MITM_LIMITS.maxParametersPerEndpoint + 1 },
            (_, index) => ({
              name: `p${String(index)}`,
              location: "query" as const,
              type: "string" as const,
            }),
          ),
        },
      }),
    );
    for (let index = 0; index <= MITM_LIMITS.maxStatusCodes; index += 1)
      inventory.applyFlow(
        flow(index + 2, {
          response: { ...flow(index + 2).response!, status: 200 + index },
        }),
      );
    const snapshot = inventory.snapshot();
    const endpoint = snapshot.endpoints[0];
    expect(endpoint?.parameters).toHaveLength(
      MITM_LIMITS.maxParametersPerEndpoint,
    );
    expect(endpoint?.request_header_names).toHaveLength(
      MITM_LIMITS.maxHeaderNames,
    );
    expect(endpoint?.status_histogram).toHaveLength(MITM_LIMITS.maxStatusCodes);
    expect(snapshot.totals.facts_omitted).toBeGreaterThan(0);
  });
});
