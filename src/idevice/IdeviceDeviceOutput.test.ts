import { describe, expect, it } from "vitest";

import { parseIdeviceAppsOutput } from "./IdeviceDeviceOutput.js";

describe("parseIdeviceAppsOutput", () => {
  it("parses a bare array inventory the launcher prints", () => {
    const parsed = parseIdeviceAppsOutput(
      JSON.stringify([
        {
          CFBundleIdentifier: "com.fixture.app",
          CFBundleName: "Fixture",
          CFBundleShortVersionString: "2.1.0",
          signer_is_restricted: true,
        },
      ]) + "\n",
    );
    expect(parsed.apps).toEqual([
      {
        bundle_id: "com.fixture.app",
        name: "Fixture",
        version: "2.1.0",
        signer_restricted: true,
        fields: [
          { key: "CFBundleName", value: "Fixture" },
          { key: "CFBundleShortVersionString", value: "2.1.0" },
          { key: "signer_is_restricted", value: "true" },
        ],
      },
    ]);
    expect(parsed.unparsedLines).toEqual([]);
  });

  it("accepts the wrapped {apps: [...]} document with the same row facts", () => {
    const rows = [
      {
        bundle_id: "com.fixture.app",
        name: "Fixture",
        team_name: "Fixture Team",
      },
    ];
    const bare = parseIdeviceAppsOutput(JSON.stringify(rows));
    const wrapped = parseIdeviceAppsOutput(JSON.stringify({ apps: rows }));
    expect(wrapped.apps).toEqual(bare.apps);
    expect(wrapped.unparsedLines).toEqual(bare.unparsedLines);
    expect(wrapped.apps[0]?.bundle_id).toBe("com.fixture.app");
  });

  it("reports an object without an apps array as unparsed, not as an empty inventory", () => {
    const parsed = parseIdeviceAppsOutput(
      JSON.stringify({ not: "an app inventory" }),
    );
    expect(parsed.apps).toEqual([]);
    expect(parsed.unparsedLines.length).toBeGreaterThan(0);
  });

  it("reports unparseable output through its leading lines", () => {
    const parsed = parseIdeviceAppsOutput("apps error: unavailable\n");
    expect(parsed.apps).toEqual([]);
    expect(parsed.unparsedLines[0]).toContain("apps error");
  });
});
