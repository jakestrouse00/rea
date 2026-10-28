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
 * verified View8 release is pinned; the cached-data header decode is pinned to
 * the Node 24 and Node 26 V8 lines and to one documented bytenode-era layout.
 */
export const VIEW8_LANE_UNVERIFIED_NOTE =
  "View8's command line and disassembly text are documented assumptions and no verified View8 release is pinned; this lane decodes the cached-data header itself against pinned layouts and reports disassembly digest and size only.";

/**
 * Resource policy for this lane. The values are owned by the domain so that
 * non-provider layers can cite them without importing provider construction;
 * the lane re-exports them from its own constants module.
 */
export {
  DEFAULT_VIEW8_OPERATION_TIMEOUT_MS,
  VIEW8_MAX_INPUT_BYTES,
  VIEW8_MAX_OUTPUT_BYTES,
} from "../../domain/javascript/v8Bytecode.js";

/**
 * High 16 bits of V8's cached-data magic. Some builds XOR the low bits with
 * their external-reference count, so only the marker bits are compared.
 */
export const V8_CACHED_DATA_MAGIC = 0xc0de_0000;
