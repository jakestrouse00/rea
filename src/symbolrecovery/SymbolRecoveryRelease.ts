/** Stable provider identity and caller-facing remediation for symbol recovery. */
export const SYMBOL_PROVIDER_ID = "symbols";

/** Provider name used in Evidence provenance. */
export const SYMBOL_PROVIDER_NAME =
  "symbol recovery (GoReSym, rustfilt, dump_syms)";

/** Environment key selecting the caller's GoReSym executable. */
export const GORESYM_COMMAND_ENV = "REA_GORESYM_COMMAND";

/** Environment key selecting a caller's rustfilt executable. */
export const RUSTFILT_COMMAND_ENV = "REA_RUSTFILT_COMMAND";

/** Environment key selecting the caller's dump_syms executable. */
export const DUMP_SYMS_COMMAND_ENV = "REA_DUMP_SYMS_COMMAND";

/** Remediation for an unset or unusable GoReSym selection. */
export const GORESYM_COMMAND_REMEDIATION = `Install GoReSym for this host or point ${GORESYM_COMMAND_ENV} at an absolute path to an existing GoReSym binary. REA never downloads, installs, or updates it`;

/** Remediation for an unset or unusable rustfilt selection. */
export const RUSTFILT_COMMAND_REMEDIATION = `Install rustfilt (cargo install rustfilt) or point ${RUSTFILT_COMMAND_ENV} at an absolute path to an existing rustfilt binary. When the setting is unset REA resolves rustfilt from PATH`;

/** Remediation for an unset or unusable dump_syms selection. */
export const DUMP_SYMS_COMMAND_REMEDIATION = `Install Breakpad dump_syms for this host or point ${DUMP_SYMS_COMMAND_ENV} at an absolute path to an existing dump_syms binary. REA never downloads, installs, or updates it`;

/**
 * The producer argv and output shapes in this lane are documented
 * assumptions. No verified release of any of the three tools is pinned.
 */
export const SYMBOL_LANE_UNVERIFIED_NOTE =
  "The GoReSym, rustfilt, and dump_syms shapes in this lane are documented assumptions; no verified release is pinned yet.";
