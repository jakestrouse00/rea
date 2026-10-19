import { describe, expect, it } from "vitest";
import {
  RISK_PLANE_ADVISORY_LIMITATION,
  RISK_PLANE_ADVISORY_SOURCE_KIND,
  riskPlaneAdvisoriesForValues,
  riskPlaneAdvisoryMatches,
} from "./riskPlaneAdvisories.js";

describe("reported anti-bot vendor advisory applicability", () => {
  it.each([
    "challenges.cloudflare.com",
    "www.cloudflare.com",
    "a1b2c3d4.ams02.edge.compute.cloudflare.com",
    "e23f0-27.d.akamai.net",
    "a.b.akamaihd.net",
    "js.datadome.co",
    "geo.captcha-delivery.co.datadome.co",
    "client.perimeterx.net",
    "cdn.perimeterx.humansecurity.com",
    "telemetry.radwarecloud.com",
    "script.kasada.io",
  ])(
    "discloses the vendor advisory for retained value %s without claiming behavior",
    (value) => {
      const matches = riskPlaneAdvisoryMatches(value);
      expect(matches.length).toBeGreaterThan(0);
      for (const match of matches) {
        expect(match.source_kind).toBe("public-documentation");
        expect(match.mechanism_summary).not.toMatch(
          /spoof|bypass|evade|rotate|forge/iu,
        );
        expect(match.caveats.length).toBeGreaterThan(0);
      }
      const strings = riskPlaneAdvisoriesForValues([value]);
      expect(strings.length).toBeGreaterThan(0);
      for (const advisory of strings) {
        expect(advisory).toContain(JSON.stringify(value.toLowerCase()));
        expect(advisory).toContain(RISK_PLANE_ADVISORY_LIMITATION);
        expect(advisory).toContain("Public defensive documentation: https://");
        expect(advisory).not.toMatch(/\b(?:spoof|bypass|evade)\w*/iu);
      }
    },
  );

  it.each([
    "example.com",
    "example.invalid",
    ".cloudflare.com.example.org",
    "akamai.net.evil.example",
    "notdatadome.col",
    "localhost",
    "192.0.2.10",
  ])("does not attach a vendor advisory to %s", (value) => {
    expect(riskPlaneAdvisoryMatches(value)).toEqual([]);
    expect(riskPlaneAdvisoriesForValues([value])).toEqual([]);
  });

  it("deduplicates vendors and retained values across one disclosure pass", () => {
    const strings = riskPlaneAdvisoriesForValues([
      "js.datadome.co",
      "JS.DATADOME.CO",
      "www.cloudflare.com",
      "challenges.cloudflare.com",
    ]);
    expect(strings).toHaveLength(2);
    expect(strings[0]).toContain("js.datadome.co");
    expect(strings.every((advisory) => advisory.includes(".com"))).toBe(false);
  });

  it("records every advisory as public-documentation kind with the presence limitation", () => {
    expect(RISK_PLANE_ADVISORY_SOURCE_KIND).toBe("public-documentation");
    expect(RISK_PLANE_ADVISORY_LIMITATION).toContain(
      "observational disclosure only",
    );
    expect(RISK_PLANE_ADVISORY_LIMITATION).toContain(
      "does not establish behavior",
    );
  });
});
