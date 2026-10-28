/**
 * Curated OUI subset for device-evidence correlation.
 *
 * Provenance: IEEE Registration Authority public MA-L registry, verified
 * against the registry-derived vendor listings at authoring time (October
 * 2026). This is a deliberately small, non-exhaustive snapshot: it covers the
 * OUIs visible in this repository's existing discovery test fixtures plus a
 * handful of common consumer vendors. It is never refreshed at runtime and no
 * network calls are made. Every classification produced from this table is a
 * derived "probably" claim, not an observed fact. Addresses whose prefix is
 * absent from this table keep vendor null; absence here is not evidence that
 * the prefix is unregistered.
 */
const CURATED_OUI_SUBSET: Readonly<Record<string, string>> = {
  "00:00:0c": "Cisco Systems",
  "00:03:93": "Apple, Inc.",
  "00:05:85": "Juniper Networks",
  "00:0c:8a": "Bose Corporation",
  "00:18:0a": "Cisco Meraki",
  "00:1b:21": "Intel Corporate",
  "04:52:c7": "Bose Corporation",
  "04:5c:6c": "Juniper Networks",
  "08:df:1f": "Bose Corporation",
  "28:11:a5": "Bose Corporation",
  "3c:22:fb": "Apple, Inc.",
  "8c:1d:96": "Intel Corporate",
  "a4:83:e7": "Apple, Inc.",
  "f0:18:98": "Apple, Inc.",
};

export const ouiPrefix = (normalizedAddress: string): string | null => {
  const groups = normalizedAddress.split(":");
  return groups.length === 6 ? groups.slice(0, 3).join(":") : null;
};

export const ouiVendorFromTable = (prefix: string): string | null =>
  CURATED_OUI_SUBSET[prefix.toLowerCase()] ?? null;

export const ouiVendorSearchToken = (vendor: string): string =>
  vendor.split(/[ ,]/u)[0]?.toLowerCase() ?? "";
