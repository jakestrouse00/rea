import { describe, expect, it } from "vitest";

import {
  REPLAY_ALLOWED_ORIGINS_ENV,
  ReplayConfigurationFailure,
  normalizedReplayOrigin,
  parseReplayAllowedOrigins,
  replayUrlApproval,
} from "./replayOrigins.js";

const codes = (encoded: string | undefined): string | undefined => {
  const parsed = parseReplayAllowedOrigins(encoded);
  return parsed.ok ? "ok" : parsed.error.code;
};

describe("replay operator allowlist", () => {
  it("stays disabled when the setting is absent, empty, or names no origin", () => {
    expect(codes(undefined)).toBe("not_configured");
    expect(codes("  ")).toBe("not_configured");
    expect(codes("[]")).toBe("not_configured");
    const refused = parseReplayAllowedOrigins(undefined);
    expect(refused.ok).toBe(false);
    if (refused.ok) return;
    expect(refused.error.diagnostics.setting).toBe(REPLAY_ALLOWED_ORIGINS_ENV);
    expect(String(refused.error.diagnostics.remediation)).toContain(
      REPLAY_ALLOWED_ORIGINS_ENV,
    );
  });

  it("rejects malformed encodings instead of dropping entries", () => {
    expect(codes("{")).toBe("invalid_encoding");
    expect(codes('"https://a.test"')).toBe("invalid_encoding");
    expect(codes("[1]")).toBe("invalid_encoding");
    expect(codes("null")).toBe("invalid_encoding");
  });

  it("rejects entries that are not exact origins and names the entry", () => {
    for (const value of [
      "https://a.test/path",
      "https://a.test?x=1",
      "https://a.test#f",
      "https://user:pass@a.test",
      "ftp://a.test",
      "*.a.test",
      "a.test",
    ]) {
      const parsed = parseReplayAllowedOrigins(JSON.stringify([value]));
      expect(parsed.ok).toBe(false);
      if (parsed.ok) continue;
      expect(parsed.error).toBeInstanceOf(ReplayConfigurationFailure);
      expect(parsed.error.code).toBe("invalid_origin");
      expect(parsed.error.diagnostics.entry).toBe(0);
    }
  });

  it("normalizes and deduplicates approved origins", () => {
    const parsed = parseReplayAllowedOrigins(
      JSON.stringify([
        "https://API.Example.test:443/",
        "https://api.example.test",
        "http://127.0.0.1:8080",
      ]),
    );
    expect(parsed.ok).toBe(true);
    expect(parsed.ok ? parsed.value : []).toEqual([
      "https://api.example.test",
      "http://127.0.0.1:8080",
    ]);
    expect(normalizedReplayOrigin("https://A.test:443/")).toBe(
      "https://a.test",
    );
  });
});

describe("replay URL approval", () => {
  const allowed = ["https://api.example.test"];

  it("approves only allowlisted http(s) origins without userinfo", () => {
    expect(
      replayUrlApproval("https://api.example.test/v1/x?y=1", allowed),
    ).toEqual({
      approved: true,
      url: "https://api.example.test/v1/x?y=1",
      origin: "https://api.example.test",
    });
    expect(
      replayUrlApproval("https://api.example.test.evil.test/x", allowed),
    ).toMatchObject({ approved: false });
    expect(
      replayUrlApproval("http://api.example.test/", allowed),
    ).toMatchObject({ approved: false });
    expect(
      replayUrlApproval("https://user:pw@api.example.test/", allowed),
    ).toEqual({
      approved: false,
      reason:
        "the request URL carries userinfo; replay credentials belong in headers",
    });
    expect(replayUrlApproval("not a url", allowed)).toMatchObject({
      approved: false,
    });
    expect(replayUrlApproval("file:///etc/passwd", allowed)).toMatchObject({
      approved: false,
    });
  });
});
