/** Stable provider identity and caller-facing remediation for the YARA-X lane. */
export const YARA_PROVIDER_ID = "yara-x";

/** Provider name used in Evidence provenance. */
export const YARA_PROVIDER_NAME = "VirusTotal YARA-X (rule scanning)";

/** Environment key selecting the caller's YARA-X `yr` executable. */
export const YARAX_COMMAND_ENV = "REA_YARAX_COMMAND";

/** Remediation for an unset or unusable YARA-X selection. */
export const YARAX_COMMAND_REMEDIATION = `Install YARA-X for this host (cargo install yara-x-cli or a published release) or point ${YARAX_COMMAND_ENV} at an absolute path to an existing \`yr\` executable. REA never downloads, installs, or updates it`;

/** Remediation for malformed YARA-X output rather than a missing tool. */
export const YARAX_VERSION_PROBE_REMEDIATION = `Confirm the selected ${YARAX_COMMAND_ENV} binary answers \`yr --version\`. REA records no version when the probe cannot recognize its output`;

/** Identity of REA's own curated crypto-constant rule pack. */
export const YARA_CRYPTO_PACK = {
  id: "rea-crypto-constants",
  version: 1,
  directory: "../../third_party/yara-rules/crypto",
  ruleFile: "crypto-constants.yar",
  manifestFile: "manifest.json",
} as const;

/** Remediation when the vendored pack is missing or does not match its manifest. */
export const YARA_CRYPTO_PACK_REMEDIATION = `Reinstall REA from a verified package: the bundled ${YARA_CRYPTO_PACK.id} rule pack is missing or does not match ${YARA_CRYPTO_PACK.manifestFile}. REA never downloads a replacement`;

/**
 * YARA-X JSON fields are asserted from its documented `--output-format=json`
 * shape. No verified YARA-X release is pinned; every result carries this note.
 */
export const YARAX_LANE_UNVERIFIED_NOTE =
  "The YARA-X JSON fields in this lane are documented assumptions; no verified YARA-X release is pinned yet.";
