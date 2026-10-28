import { describe, expect, it } from "vitest";

import {
  REPLAY_CREDENTIAL_HEADERS,
  isReplayCredentialHeader,
  redactedReplayLocation,
  redactedReplayUrl,
  replayCredentialHeaderNames,
  replayHeaderNames,
  replayRequestEcho,
} from "./replayRedaction.js";

const SECRET = "Bearer sk-live-0123456789";

describe("replay credential vocabulary", () => {
  it("matches the declared names case-insensitively and nothing else", () => {
    for (const name of REPLAY_CREDENTIAL_HEADERS)
      expect(isReplayCredentialHeader(name.toUpperCase())).toBe(true);
    for (const name of ["content-type", "accept", "x-trace-id", "location"])
      expect(isReplayCredentialHeader(name)).toBe(false);
  });

  it("discloses credential header names once, preserving observed spelling", () => {
    expect(
      replayCredentialHeaderNames([
        { name: "Authorization", value: SECRET },
        { name: "authorization", value: "again" },
        { name: "cookie", value: "a=1" },
        { name: "accept", value: "*/*" },
        { name: "Set-Cookie", value: "b=2" },
      ]),
    ).toEqual(["Authorization", "cookie", "Set-Cookie"]);
    expect(
      replayHeaderNames([
        { name: "Accept", value: "a" },
        { name: "accept", value: "b" },
      ]),
    ).toEqual(["Accept"]);
  });
});

describe("replay echoed forms", () => {
  const request = {
    method: "POST",
    url: "https://api.example.test/v1/items",
    headers: [
      { name: "authorization", value: SECRET },
      { name: "cookie", value: "session=abc" },
      { name: "content-type", value: "application/json" },
    ],
    body: { kind: "text", text: '{"card":"4111111111111111"}' } as const,
  };

  it("echoes names and sizes without any header or body value", () => {
    const echo = replayRequestEcho(request);
    const serialized = JSON.stringify(echo);
    expect(echo).toEqual({
      method: "POST",
      url: "https://api.example.test/v1/items",
      origin: "https://api.example.test",
      header_names: ["authorization", "cookie", "content-type"],
      credential_header_names: ["authorization", "cookie"],
      body_bytes: Buffer.byteLength('{"card":"4111111111111111"}', "utf8"),
      body_present: true,
    });
    expect(serialized).not.toContain(SECRET);
    expect(serialized).not.toContain("session=abc");
    expect(serialized).not.toContain("4111111111111111");
  });

  it("strips URL userinfo from every echoed location", () => {
    expect(redactedReplayUrl("https://user:pw@api.example.test/x?y=1")).toBe(
      "https://api.example.test/x?y=1",
    );
    expect(redactedReplayUrl("/next", "https://api.example.test/a")).toBe(
      "https://api.example.test/next",
    );
    expect(
      redactedReplayLocation("http://user:pw@other.test/x", "https://a.test/"),
    ).toBe("http://other.test/x");
    expect(
      redactedReplayLocation("http://user:pw@[bad", "https://a.test/"),
    ).toBe("http://[bad");
  });
});
