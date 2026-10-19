import { describe, expect, it } from "vitest";

import {
  MAX_WEBEXT_MANIFEST_BYTES,
  parseWebExtensionManifest,
} from "./webExtensionManifest.js";
import { ContainerFormatError } from "./containerFormatError.js";

const encodeManifest = (value: unknown): Buffer =>
  Buffer.from(JSON.stringify(value), "utf8");

describe("parseWebExtensionManifest", () => {
  it("projects the MV3 permission surface value-free", () => {
    const manifest = parseWebExtensionManifest(
      encodeManifest({
        name: "Sample Extension",
        version: "1.2.3",
        manifest_version: 3,
        permissions: ["storage", "tabs"],
        host_permissions: ["*://*.example.com/*"],
        background: { service_worker: "background.js" },
        content_scripts: [
          { matches: ["https://example.com/*"], js: ["content.js"], css: [] },
        ],
        browser_specific_settings: undefined,
        unused_member: true,
      }),
    );
    expect(manifest.name).toBe("Sample Extension");
    expect(manifest.version).toBe("1.2.3");
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions).toEqual(["storage", "tabs"]);
    expect(manifest.host_permissions).toEqual(["*://*.example.com/*"]);
    expect(manifest.background_service_worker).toBe("background.js");
    expect(manifest.background_scripts).toEqual([]);
    expect(manifest.content_scripts).toEqual([
      { matches: ["https://example.com/*"], js: ["content.js"], css: [] },
    ]);
    expect(manifest.browser_specific_settings).toBe(null);
    expect(manifest.unrecognized_member_count).toBe(1);
  });

  it("projects MV2 background scripts and gecko settings", () => {
    const manifest = parseWebExtensionManifest(
      encodeManifest({
        manifest_version: 2,
        background: { scripts: ["bg1.js", "bg2.js"] },
        permissions: ["<all_urls>"],
        browser_specific_settings: {
          gecko: { id: "sample@example.com", strict_min_version: "115.0" },
        },
      }),
    );
    expect(manifest.manifest_version).toBe(2);
    expect(manifest.background_service_worker).toBe(null);
    expect(manifest.background_scripts).toEqual(["bg1.js", "bg2.js"]);
    expect(manifest.browser_specific_settings).toEqual({
      id: "sample@example.com",
      strict_min_version: "115.0",
    });
  });

  it("counts unrecognized manifest_version values as unknown", () => {
    const manifest = parseWebExtensionManifest(
      encodeManifest({ manifest_version: 42, name: "x" }),
    );
    expect(manifest.manifest_version).toBe(null);
    expect(manifest.name).toBe("x");
  });

  it("rejects malformed JSON and non-object roots with typed failures", () => {
    expect(() =>
      parseWebExtensionManifest(Buffer.from("{oops", "utf8")),
    ).toThrowError(ContainerFormatError);
    expect(() =>
      parseWebExtensionManifest(Buffer.from("[1,2,3]", "utf8")),
    ).toThrowError(/JSON object/u);
  });

  it("refuses manifests beyond the byte budget with a typed limit", () => {
    expect(() =>
      parseWebExtensionManifest(
        Buffer.alloc(MAX_WEBEXT_MANIFEST_BYTES + 1, 0x20),
      ),
    ).toThrowError(/read budget/u);
  });

  it("truncates oversized content-script collections with a limitation", () => {
    const scripts = Array.from({ length: 1500 }, (_, index) => ({
      matches: [`https://${String(index)}.example.com/*`],
      js: [],
      css: [],
    }));
    const manifest = parseWebExtensionManifest(
      encodeManifest({ content_scripts: scripts }),
    );
    expect(manifest.content_scripts).toHaveLength(1024);
    expect(
      manifest.limitations.some((line) =>
        line.includes("truncated to the first 1024"),
      ),
    ).toBe(true);
  });
});
