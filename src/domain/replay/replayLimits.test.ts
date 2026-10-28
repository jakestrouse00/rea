import { describe, expect, it } from "vitest";

import {
  replayContentTypeClass,
  replaySizeClass,
  replayStatusClass,
} from "./replayLimits.js";

describe("replay observation classifications", () => {
  it("classifies every status band without inferring a challenge", () => {
    expect(replayStatusClass(100)).toBe("informational");
    expect(replayStatusClass(199)).toBe("informational");
    expect(replayStatusClass(200)).toBe("success");
    expect(replayStatusClass(299)).toBe("success");
    expect(replayStatusClass(301)).toBe("redirect");
    expect(replayStatusClass(399)).toBe("redirect");
    expect(replayStatusClass(403)).toBe("client_error");
    expect(replayStatusClass(429)).toBe("client_error");
    expect(replayStatusClass(499)).toBe("client_error");
    expect(replayStatusClass(500)).toBe("server_error");
    expect(replayStatusClass(599)).toBe("server_error");
    expect(replayStatusClass(600)).toBe("unknown");
    expect(replayStatusClass(999)).toBe("unknown");
  });

  it("buckets body sizes at their inclusive upper bounds", () => {
    expect(replaySizeClass(0)).toBe("empty");
    expect(replaySizeClass(1)).toBe("up_to_1_kib");
    expect(replaySizeClass(1_024)).toBe("up_to_1_kib");
    expect(replaySizeClass(1_025)).toBe("up_to_64_kib");
    expect(replaySizeClass(64 * 1_024)).toBe("up_to_64_kib");
    expect(replaySizeClass(1_024 * 1_024)).toBe("up_to_1_mib");
    expect(replaySizeClass(8 * 1_024 * 1_024)).toBe("up_to_8_mib");
    expect(replaySizeClass(8 * 1_024 * 1_024 + 1)).toBe("over_8_mib");
  });

  it("keeps an absent, unknown, and recognized content type distinct", () => {
    expect(replayContentTypeClass(undefined)).toBe("absent");
    expect(replayContentTypeClass("")).toBe("unknown");
    expect(replayContentTypeClass("garbage")).toBe("unknown");
    expect(replayContentTypeClass("application/json; charset=utf-8")).toBe(
      "json",
    );
    expect(replayContentTypeClass("application/vnd.api+json")).toBe("json");
    expect(replayContentTypeClass("text/html;charset=UTF-8")).toBe("html");
    expect(replayContentTypeClass("application/soap+xml")).toBe("xml");
    expect(replayContentTypeClass("text/xml")).toBe("xml");
    expect(replayContentTypeClass("application/javascript")).toBe("javascript");
    expect(replayContentTypeClass("text/css")).toBe("css");
    expect(replayContentTypeClass("text/plain")).toBe("text");
    expect(replayContentTypeClass("application/octet-stream")).toBe("binary");
    expect(replayContentTypeClass("application/x-www-form-urlencoded")).toBe(
      "text",
    );
    expect(replayContentTypeClass("image/png")).toBe("image");
    expect(replayContentTypeClass("video/mp4")).toBe("audio_video");
    expect(replayContentTypeClass("font/woff2")).toBe("font");
    expect(replayContentTypeClass("multipart/form-data; boundary=x")).toBe(
      "multipart",
    );
  });
});
