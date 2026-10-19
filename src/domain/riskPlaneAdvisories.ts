/**
 * Anti-bot vendor-plane observational advisories, maintained in the same
 * disclose-only style as the apktool version advisories. Every entry:
 * - describes publicly documented defensive product behavior,
 * - is keyed by host suffixes a caller-supplied capture may already retain,
 * - claims presence only, never behavior, enforcement or outcome for the
 *   caller's own session.
 * This table contains no evasion guidance, no bypass techniques and no
 * credential or fingerprint-spoofing instructions, and must stay that way.
 */

export const RISK_PLANE_ADVISORY_SOURCE_KIND = "public-documentation" as const;

/** Suffix match is case-insensitive and label-aligned ("." boundary only). */
export interface RiskPlaneVendorAdvisory {
  readonly vendor: string;
  /** Documented host suffixes through which the vendor's plane is observed. */
  readonly observed_via: readonly string[];
  /** Publicly documented defensive facts only; one or two sentences. */
  readonly mechanism_summary: string;
  readonly source_kind: typeof RISK_PLANE_ADVISORY_SOURCE_KIND;
  readonly caveats: string;
  readonly source_url: string;
}

export const RISK_PLANE_ADVISORY_LIMITATION =
  "Vendor-host presence does not establish behavior, enforcement, an engagement outcome or that any interception applies to the caller's session; suffix matching alone cannot attribute a specific product when a vendor also operates other services on its domains; observational disclosure only.";

const advisories: readonly RiskPlaneVendorAdvisory[] = [
  {
    vendor: "Cloudflare",
    observed_via: ["cloudflare.com"],
    mechanism_summary:
      "Cloudflare's publicly documented bot management and Turnstile products issue managed challenges and Turnstile widgets to browser clients and evaluate client signals to classify automated traffic before it reaches an origin.",
    source_kind: RISK_PLANE_ADVISORY_SOURCE_KIND,
    caveats:
      "cloudflare.com hosts also serve unrelated Cloudflare services and public documentation, so a suffix match alone does not attribute a specific product.",
    source_url: "https://developers.cloudflare.com/bots/",
  },
  {
    vendor: "Akamai",
    observed_via: ["akamai.net", "akamaihd.net"],
    mechanism_summary:
      "Akamai's publicly documented Bot Manager products evaluate request patterns and client attributes at edge sensors and can apply rate limits, delays or interstitial challenges to traffic classified as automated.",
    source_kind: RISK_PLANE_ADVISORY_SOURCE_KIND,
    caveats:
      "akamai.net and akamaihd.net hosts are edge content-delivery hostnames whose presence does not by itself identify bot-management action.",
    source_url: "https://techdocs.akamai.com/bot-manager/docs/",
  },
  {
    vendor: "DataDome",
    observed_via: ["datadome.co"],
    mechanism_summary:
      "DataDome's publicly documented bot protection instructs sites to load a DataDome script and can redirect clients to its CAPTCHA or challenge endpoints when traffic is classified as automated.",
    source_kind: RISK_PLANE_ADVISORY_SOURCE_KIND,
    caveats:
      "datadome.co endpoints serve the protection plane for protected sites only when the site's integration references them; first-time observation does not prove an active enforcement decision.",
    source_url: "https://docs.datadome.co/",
  },
  {
    vendor: "HUMAN Security (PerimeterX)",
    observed_via: ["perimeterx.net", "humansecurity.com"],
    mechanism_summary:
      "HUMAN Security's publicly documented products (formerly PerimeterX) load sensor scripts on integrated sites and can present human-challenge pages to clients whose signals are classified as automated.",
    source_kind: RISK_PLANE_ADVISORY_SOURCE_KIND,
    caveats:
      "PerimeterX-era hostnames persist for older integrations; host presence does not establish which product generation or enforcement policy applies.",
    source_url: "https://docs.humansecurity.com/docs/",
  },
  {
    vendor: "Radware",
    observed_via: ["radwarecloud.com"],
    mechanism_summary:
      "Radware's publicly documented Bot Manager issues browser-facing challenge endpoints under its cloud domains to verify that clients are operated by a real browser before serving protected origins.",
    source_kind: RISK_PLANE_ADVISORY_SOURCE_KIND,
    caveats:
      "radwarecloud.com also hosts other Radware cloud services; suffix matching alone does not attribute bot management.",
    source_url: "https://www.radware.com/products/botmanager/",
  },
  {
    vendor: "Kasada",
    observed_via: ["kasada.io"],
    mechanism_summary:
      "Kasada's publicly documented bot mitigation serves edge scripts through protected origins' domains and uses interactive challenge content classified at its edge to distinguish automated clients.",
    source_kind: RISK_PLANE_ADVISORY_SOURCE_KIND,
    caveats:
      "kasada.io endpoints are reached only through integrations that reference them; presence does not establish a challenge outcome.",
    source_url: "https://www.kasada.io/solutions/bot-protection/",
  },
];

const isLabelSuffix = (value: string, suffix: string): boolean =>
  value === suffix || value.endsWith(`.${suffix}`);

/**
 * Match one retained host-like value against every documentation-backed
 * vendor suffix. Returns all matches, without order-dependent truncation.
 */
export const riskPlaneAdvisoryMatches = (
  value: string,
): readonly RiskPlaneVendorAdvisory[] => {
  const normalized = value.trim().toLowerCase();
  return advisories.filter((entry) =>
    entry.observed_via.some((suffix) => isLabelSuffix(normalized, suffix)),
  );
};

/**
 * Format retained values' matches into caller-facing advisory strings. Every
 * string carries the vendor, the retained values, the public defensive
 * summary, its caveats, the documentation pointer, and the
 * observational-presence limitation — the same disclose-and-verify posture as
 * the apktool version advisories. One string per matched vendor.
 */
export const riskPlaneAdvisoriesForValues = (
  values: readonly string[],
): readonly string[] => {
  const matched = new Map<
    string,
    { readonly advisory: RiskPlaneVendorAdvisory; readonly observed: string[] }
  >();
  for (const value of values) {
    const normalized = value.trim().toLowerCase();
    for (const match of riskPlaneAdvisoryMatches(value)) {
      const entry = matched.get(match.vendor);
      if (entry !== undefined) {
        if (!entry.observed.includes(normalized))
          entry.observed.push(normalized);
        continue;
      }
      matched.set(match.vendor, { advisory: match, observed: [normalized] });
    }
  }
  return [...matched.values()].map(({ advisory, observed }) =>
    [
      `Observed values ${JSON.stringify(observed)} resolve under anti-bot vendor ${JSON.stringify(advisory.vendor)}.`,
      advisory.mechanism_summary,
      `Caveats: ${advisory.caveats}`,
      `Public defensive documentation: ${advisory.source_url}`,
      RISK_PLANE_ADVISORY_LIMITATION,
    ].join(" "),
  );
};
