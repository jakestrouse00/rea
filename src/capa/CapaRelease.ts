/** Stable provider identity and caller-facing remediation for the capa lane. */
export const CAPA_PROVIDER_ID = "capa";

/** Provider name used in Evidence provenance. */
export const CAPA_PROVIDER_NAME = "mandiant/capa (capability matching)";

/** Environment key selecting the caller's capa executable. */
export const CAPA_COMMAND_ENV = "REA_CAPA_COMMAND";

/** Remediation for an unset or unusable capa selection. */
export const CAPA_COMMAND_REMEDIATION = `Install capa for this host (pip install flare-capa) or point ${CAPA_COMMAND_ENV} at an absolute path to an existing capa executable. REA never downloads, installs, or updates it`;

/** Remediation for malformed capa output rather than a missing tool. */
export const CAPA_VERSION_PROBE_REMEDIATION = `Confirm the selected ${CAPA_COMMAND_ENV} binary answers \`capa --version\`. REA records no version when the probe cannot recognize its output`;

/**
 * The capa JSON document shape differs across releases. Only the rule
 * inventory consumed here is asserted, and every result carries this note
 * until a maintainer lane pins a release.
 */
export const CAPA_LANE_UNVERIFIED_NOTE =
  "The capa JSON fields in this lane are documented assumptions; no verified capa release is pinned yet.";
