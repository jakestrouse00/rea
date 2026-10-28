/** Stable provider identity and caller-facing remediation for V8 bytecode disassembly. */
export const VIEW8_PROVIDER_ID = "view8";

/** Provider name used in Evidence provenance. */
export const VIEW8_PROVIDER_NAME = "V8 bytecode disassembly (View8)";

/** Environment key selecting a locally built View8 launcher. */
export const VIEW8_COMMAND_ENV = "REA_VIEW8_COMMAND";

/** Remediation for an unset or unusable View8 selection. */
export const VIEW8_REMEDIATION = `Build View8 with its patched V8 disassembler for this host, then point ${VIEW8_COMMAND_ENV} at an absolute path to the executable. REA never downloads, builds, or updates it; the build recipe is in docs/v8-bytecode.md`;

/** Remediation for output that carries no disassembly rather than a missing tool. */
export const VIEW8_OUTPUT_REMEDIATION = `Confirm the selected View8 launcher prints a bytecode disassembly for one cached-data file. REA records only the disassembly digest, byte and line counts, so an empty stream is reported as empty rather than repaired`;

/**
 * View8's argv shape and disassembly text are documented assumptions. No
 * verified release is pinned; the bytecode header decode is REA's own and is
 * likewise unverified against a specific V8 build.
 */
export const VIEW8_LANE_UNVERIFIED_NOTE =
  "View8's command line and disassembly text are documented assumptions and no verified View8 or V8 build is pinned; this lane parses the cached-data header itself and reports disassembly digest and size only.";

/** Fixed operation deadline for one bounded View8 run. */
export const DEFAULT_VIEW8_OPERATION_TIMEOUT_MS = 300_000;

/** Bounded capture budget for one disassembly stream. */
export const VIEW8_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

/** Bounded admission for one selected bytecode artifact. */
export const VIEW8_MAX_INPUT_BYTES = 64 * 1024 * 1024;

/**
 * High 16 bits of V8's cached-data magic. Some builds XOR the low bits with
 * their external-reference count, so only the marker bits are compared.
 */
export const V8_CACHED_DATA_MAGIC = 0xc0de_0000;

/** V8 cached-data header words before the payload. */
export const V8_CACHED_DATA_HEADER_BYTES = 24;
