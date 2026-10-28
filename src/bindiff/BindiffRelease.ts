/** Stable provider identity and caller-facing remediation for the BinDiff lane. */
export const BINDIFF_PROVIDER_ID = "bindiff";

/** Provider name used in Evidence provenance. */
export const BINDIFF_PROVIDER_NAME =
  "BinDiff (provider-backed binary comparison)";

/** Environment key selecting the caller's BinDiff adapter command. */
export const BINDIFF_COMMAND_ENV = "REA_BINDIFF_COMMAND";

/** Environment key selecting the caller's BinExport exporter command. */
export const BINEXPORT_COMMAND_ENV = "REA_BINEXPORT_COMMAND";

/** Remediation for an unset or unusable BinDiff selection. */
export const BINDIFF_COMMAND_REMEDIATION = `Install BinDiff 8 (open source) and point ${BINDIFF_COMMAND_ENV} at an absolute path to a command that prints the REA adapter JSON match table. REA never downloads, installs, or updates it`;

/** Remediation for an unset or unusable BinExport exporter selection. */
export const BINEXPORT_COMMAND_REMEDIATION = `Build the BinExport Ghidra extension (recipe in docs/binary-diffing.md) or point ${BINEXPORT_COMMAND_ENV} at an absolute path to a headless exporter command that writes a .BinExport file into the supplied output directory. REA never downloads, installs, or builds it`;

/** Remediation for malformed adapter output. */
export const BINDIFF_OUTPUT_REMEDIATION = `Confirm the selected BinDiff adapter prints the documented JSON object with a matches array. REA reports no partial success when the match table cannot be recognized`;

/**
 * BinDiff and BinExport command/output shapes are documented assumptions. No
 * verified upstream release is pinned.
 */
export const BINDIFF_LANE_UNVERIFIED_NOTE =
  "The BinDiff adapter JSON and BinExport exporter shapes in this lane are documented assumptions; no verified release is pinned yet.";

/** First four ASCII bytes of a BinExport protobuf. */
export const BINEXPORT_MAGIC = "BINE";
