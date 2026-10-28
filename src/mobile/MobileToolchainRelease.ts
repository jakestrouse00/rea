/** Stable identity, environment settings, and fixed bounds for the mobile lane. */

export const MOBILE_TOOLCHAIN_PROVIDER_ID = "mobile-toolchain";
export const MOBILE_TOOLCHAIN_PROVIDER_NAME =
  "Mobile runtime and forensic toolchain";

/** Caller-selected objection launcher (GPL-3.0 upstream, subprocess only). */
export const OBJECTION_COMMAND_ENV = "REA_OBJECTION_COMMAND";
/** Caller-supplied Python 3 with androguard v5 on its import path. */
export const ANDROGUARD_PYTHON_ENV = "REA_ANDROGUARD_PYTHON";
/** Optional directory holding the androguard bridge instead of the bundled one. */
export const ANDROGUARD_BRIDGE_DIR_ENV = "REA_ANDROGUARD_BRIDGE_DIR";
/** Caller-selected iLEAPP/ALEAPP launcher. */
export const ILEAPP_COMMAND_ENV = "REA_ILEAPP_COMMAND";

export const OBJECTION_COMMAND_REMEDIATION = `Set ${OBJECTION_COMMAND_ENV} to the absolute path of a caller-installed objection launcher. objection is GPL-3.0; REA runs it as a subprocess only, never links it, and never installs or upgrades it.`;

export const ANDROGUARD_PYTHON_REMEDIATION = `Set ${ANDROGUARD_PYTHON_ENV} to the absolute path of a Python 3 interpreter that can import androguard 5.x, or install androguard into a caller-managed environment and select that interpreter. REA never installs Python packages; the bundled bridge is bridge/mobile/androguard_bridge.py and ${ANDROGUARD_BRIDGE_DIR_ENV} may select a different copy.`;

export const ILEAPP_COMMAND_REMEDIATION = `Set ${ILEAPP_COMMAND_ENV} to the absolute path of a caller-installed iLEAPP (iOS) or ALEAPP (Android) launcher. REA never installs, upgrades, or drives these projects over the network; the tool writes its own TSV tables into the caller-selected output directory.`;

export const MOBILE_TOOLCHAIN_LANE_NOTE =
  "These tools run against a caller-supplied device, application, or artifact and their own parsing decides what is reported; REA bounds and normalizes their structure, it does not independently verify their claims.";

/** Fixed bounds that this release does not expose at runtime. */
export const MOBILE_LIMITS = {
  /** One objection stdout capture; larger output is refused, not parsed. */
  objectionStdoutBytes: 4 * 1024 * 1024,
  /** One bridge run's stdout capture. */
  bridgeStdoutBytes: 16 * 1024 * 1024,
  /** One iLEAPP run's stdout capture. */
  ileappStdoutBytes: 4 * 1024 * 1024,
  /** One retained TSV file; larger tables are refused rather than parsed. */
  forensicTableBytes: 8 * 1024 * 1024,
  /** Total retained TSV bytes across one report. */
  forensicTotalBytes: 32 * 1024 * 1024,
  /** One retained cell; longer cells are truncated with the table marked. */
  forensicCellCharacters: 512,
} as const;
