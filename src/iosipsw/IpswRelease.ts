/** Stable provider identity and caller-facing remediation for the ipsw lane. */
export const IPSW_PROVIDER_ID = "ipsw";

/** Provider name used in Evidence provenance. */
export const IPSW_PROVIDER_NAME = "blacktop/ipsw (iOS static image plane)";

/** Environment key selecting the caller's ipsw binary. */
export const IPSW_COMMAND_ENV = "REA_IPSW_COMMAND";

/** Environment key selecting the caller's dyld shared cache file or directory. */
export const IPSW_DSC_PATH_ENV = "REA_IPSW_DSC_PATH";

/**
 * Read-only default shared-cache directory on macOS. The provider probes it
 * only when the caller configured nothing; it never writes there.
 */
export const IPSW_DEFAULT_DSC_DIRECTORY =
  "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld";

/** Remediation for an unset or unusable ipsw CLI selection. */
export const IPSW_COMMAND_REMEDIATION = `Install blacktop/ipsw for this host (brew install blacktop/tap/ipsw) or point ${IPSW_COMMAND_ENV} at an absolute path to an existing ipsw binary. REA never downloads, installs, or updates it`;

/** Remediation for an unset or unusable shared-cache selection. */
export const IPSW_DSC_PATH_REMEDIATION = `Set ${IPSW_DSC_PATH_ENV} to an absolute dyld shared cache file or the directory that contains one, or pass cache in the request. REA never downloads iOS firmware or shared caches`;

/** Remediation for malformed CLI output rather than a missing tool. */
export const IPSW_VERSION_PROBE_REMEDIATION = `Confirm the selected ${IPSW_COMMAND_ENV} binary answers \`ipsw version\`. REA records no version when the probe cannot recognize its output`;

/**
 * The ipsw argv shapes are documented assumptions from the upstream CLI
 * reference. No verified ipsw release is pinned; every result carries this
 * note until a maintainer lane records one.
 */
export const IPSW_LANE_UNVERIFIED_NOTE =
  "The ipsw CLI argv shapes in this lane are documented assumptions; no verified ipsw release is pinned yet.";
