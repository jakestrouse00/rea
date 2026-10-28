import { describe, expect, it } from "vitest";

import {
  gattPayloadAccounting,
  parseGattLine,
  parseGattLines,
  parseGattServiceTree,
} from "./GattAnalysis.js";

describe("parseGattLine", () => {
  it("parses the known protocol events and keeps the raw line", () => {
    const line =
      '{"event":"notification","id":"aabb","ts":"2026-10-28T04:41:56.315Z","payload_hex":"3310"}';
    const parsed = parseGattLine(line);
    expect(parsed).toEqual({
      kind: "notification",
      id: "aabb",
      raw: line,
      payload_hex: "3310",
      ts: "2026-10-28T04:41:56.315Z",
      message: null,
      code: null,
    });
  });

  it("keeps unknown fields out of the typed shape but preserves them verbatim", () => {
    const line =
      '{"event":"value","id":"cc","payload_hex":"00","device_note":"kept by raw"}';
    const parsed = parseGattLine(line);
    expect(parsed.kind).toBe("value");
    expect(parsed.raw).toBe(line);
    expect(JSON.parse(parsed.raw).device_note).toBe("kept by raw");
  });

  it("normalizes odd-cased hex payloads to lowercase", () => {
    const parsed = parseGattLine(
      '{"event":"value","id":"x","payload_hex":"AB"}',
    );
    expect(parsed.payload_hex).toBe("ab");
  });

  it("sends non-JSON, unknown events and empty payloads to unparsed", () => {
    const ran = parseGattLines(
      [
        "gatt: crash trace",
        '{"event":"future_event","id":"x"}',
        '{"event":"value","id":"y","payload_hex":"not hex"}',
        '["1","2"]',
        "",
      ].join("\n"),
    );
    expect(ran.unparsedLines).toEqual([
      "gatt: crash trace",
      '{"event":"future_event","id":"x"}',
      '["1","2"]',
    ]);
    expect(ran.items).toEqual([
      {
        kind: "value",
        id: "y",
        raw: '{"event":"value","id":"y","payload_hex":"not hex"}',
        payload_hex: null,
        ts: null,
        message: null,
        code: null,
      },
    ]);
  });
});

describe("gattPayloadAccounting", () => {
  it("digests the bytes and drops the hex unless the caller opted in", () => {
    const digest = gattPayloadAccounting("33101100", false);
    expect(digest).toEqual({
      len: 4,
      sha256: expect.any(String),
      payload_hex: null,
    });
    const included = gattPayloadAccounting("33101100", true);
    expect(included?.payload_hex).toBe("33101100");
    expect(included?.sha256).toBe(digest?.sha256);
    expect(included?.len).toBe(4);
  });

  it("accounts the empty value without dropping the read", () => {
    const empty = gattPayloadAccounting("", false);
    expect(empty).toEqual({
      len: 0,
      sha256: expect.any(String),
      payload_hex: null,
    });
  });

  it("keeps a missing payload unknown", () => {
    expect(gattPayloadAccounting(null, true)).toBeNull();
  });
});

describe("parseGattServiceTree", () => {
  it("parses services and filters unknown property names", () => {
    const line = parseGattLine(
      '{"event":"connected","name":"Fake","services":[{"uuid":"180A","characteristics":[{"uuid":"2A29","properties":["read","future_property"]},{"uuid":"8E400002-F315-4F60-9FB8-838830DAEA50","properties":["write","notify"]}]}],"extra":"row"}',
    );
    const tree = parseGattServiceTree(line);
    expect(tree).toEqual(
      expect.objectContaining({
        ok: true,
      }),
    );
    if (tree.ok) {
      expect(tree.value).toEqual([
        {
          uuid: "180A",
          characteristics: [
            { uuid: "2A29", properties: ["read"] },
            {
              uuid: "8E400002-F315-4F60-9FB8-838830DAEA50",
              properties: ["write", "notify"],
            },
          ],
        },
      ]);
    }
  });

  it("keeps a peripheral without services empty", () => {
    const line = parseGattLine('{"event":"connected","name":null}');
    const tree = parseGattServiceTree(line);
    expect(tree.ok && tree.value).toEqual([]);
  });
});
