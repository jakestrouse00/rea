/** Environment variable selecting the caller-supplied Python interpreter with LIEF. */
export const LIEF_COMMAND_ENV = "REA_LIEF_COMMAND";

/** Environment variable selecting the directory holding the REA bridge script. */
export const LIEF_BRIDGE_DIR_ENV = "REA_LIEF_BRIDGE_DIR";

/** File name the selected bridge directory must provide. */
export const LIEF_BRIDGE_FILE_NAME = "lief_bridge.py";

/** Remediation when the interpreter selection is missing or not absolute. */
export const LIEF_COMMAND_REMEDIATION = `Set ${LIEF_COMMAND_ENV} to the absolute path of a caller-supplied Python 3 interpreter that has LIEF installed (BYO). REA never installs, downloads, upgrades or vendors LIEF or Python, and runs only the bridge script named by ${LIEF_BRIDGE_DIR_ENV} with that interpreter.`;

/** Remediation when the bridge directory selection is missing or incomplete. */
export const LIEF_BRIDGE_DIR_REMEDIATION = `Set ${LIEF_BRIDGE_DIR_ENV} to the absolute path of a directory holding an unmodified ${LIEF_BRIDGE_FILE_NAME} copied from this REA release (bridge/lief/${LIEF_BRIDGE_FILE_NAME}). REA reads the script and never writes, replaces or refreshes it.`;

/** Remediation when the selected interpreter cannot import LIEF. */
export const LIEF_IMPORT_REMEDIATION = `Run \`${LIEF_COMMAND_ENV}\` with \`-c 'import lief; print(lief.__version__)'\`: the interpreter must import LIEF from its own environment. Install LIEF into that interpreter yourself; REA never installs packages.`;

/** Remediation when an inspected file cannot be parsed as a supported binary. */
export const LIEF_PARSE_REMEDIATION =
  "Confirm the selected path is a complete ELF, PE, Mach-O or PDB file. A truncated, packed or non-object container is refused rather than partially reported.";

/** Remediation when the bridge emitted a frame that does not match the protocol. */
export const LIEF_PROTOCOL_REMEDIATION = `Use an unmodified ${LIEF_BRIDGE_FILE_NAME} from this release: the bridge speaks one bounded JSON frame per run on stdout and nothing else.`;

/** Stable provider identity shared by readiness, doctor and Evidence. */
export const LIEF_PROVIDER_ID = "lief";

/** Protocol version spoken by the bundled bridge and this parser. */
export const LIEF_PROTOCOL_VERSION = 1;

/**
 * Lowest LIEF release whose documented Python surface this bridge targets.
 * The declared range is an API-target range: every patch release in it is not
 * separately verified (see docs/lief-deep-parse.md).
 */
export const LIEF_MIN_SUPPORTED_VERSION = "0.14.0";

/** First LIEF major-line the bridge has not been written against. */
export const LIEF_MAX_SUPPORTED_VERSION_EXCLUSIVE = "0.17.0";

/** Fixed policy for the LIEF deep-parse lane. */
export const LIEF_LIMITS = {
  /** One request frame written to the bridge's stdin. */
  maxRequestBytes: 1 * 1_024 * 1_024,
  /** One response frame retained from the bridge's stdout. */
  maxResponseBytes: 8 * 1_024 * 1_024,
  /** Bridge stderr retained as bounded diagnostic text. */
  maxStderrBytes: 64 * 1_024,
  /** Deadline for one bridge run. */
  defaultDeadlineMs: 120_000,
  /** Deadline for the doctor's version probe. */
  doctorProbeTimeoutMs: 20_000,
  /** Output budget for the doctor's version probe. */
  doctorProbeMaxBytes: 64 * 1_024,
  /** Structure facts retained for one architecture. */
  maxArchitectures: 32,
  /** ELF dynamic entries retained. */
  maxDynamicEntries: 256,
  /** Linked library names retained for one binary. */
  maxLibraries: 256,
  /** Mach-O load commands retained. */
  maxLoadCommands: 512,
  /** PE data directory rows retained. */
  maxDataDirectories: 32,
  /** PE debug directory entries retained. */
  maxDebugEntries: 16,
  /** DWARF sections listed for one artifact. */
  maxDebugSections: 64,
  /** Lookup queries admitted in one request. */
  maxQueries: 64,
  /** Matches retained for one lookup query. */
  maxMatchesPerQuery: 16,
  /** Distinct limitation strings retained in one report. */
  maxLimitations: 32,
} as const;

/** Closed set of typed refusal codes the bridge may report. */
export const LIEF_BRIDGE_ERROR_CODES = [
  "empty_request",
  "oversized_request",
  "malformed_request",
  "unsupported_protocol",
  "unsupported_operation",
  "lief_missing",
  "artifact_unreadable",
  "artifact_mismatch",
  "unsupported_format",
  "parse_failed",
  "internal_error",
] as const;
