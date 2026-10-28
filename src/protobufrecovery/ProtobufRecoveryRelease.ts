/** Stable provider identity and caller-facing remediation for protobuf recovery. */
export const PROTOBUF_RECOVERY_PROVIDER_ID = "protobuf-recovery";

/** Provider name used in Evidence provenance. */
export const PROTOBUF_RECOVERY_PROVIDER_NAME =
  "protobuf definition recovery (pbtk, protodump, grpcurl)";

/** Environment key selecting a pbtk executable. Tried first by `auto`. */
export const PBTK_COMMAND_ENV = "REA_PBTK_COMMAND";

/** Environment key selecting a protodump executable. */
export const PROTODUMP_COMMAND_ENV = "REA_PROTODUMP_COMMAND";

/** Environment key selecting the grpcurl executable used for reflection. */
export const GRPCURL_COMMAND_ENV = "REA_GRPCURL_COMMAND";

/** Remediation for an unset protobuf recovery tool selection. */
export const PROTOBUF_RECOVERY_REMEDIATION = `Install pbtk or protodump for this host and point ${PBTK_COMMAND_ENV} or ${PROTODUMP_COMMAND_ENV} at an absolute path to the executable. REA never downloads, installs, or updates it`;

/** Remediation for an unset or unusable grpcurl selection. */
export const GRPCURL_COMMAND_REMEDIATION = `Install grpcurl for this host and point ${GRPCURL_COMMAND_ENV} at an absolute path to the executable. REA never downloads, installs, or updates it`;

/** Remediation for an unselected explicit recovery tool. */
export const PROTOBUF_TOOL_REMEDIATION = (tool: "pbtk" | "protodump"): string =>
  `Select ${tool} with an absolute ${tool === "pbtk" ? PBTK_COMMAND_ENV : PROTODUMP_COMMAND_ENV} path, or request tool=auto to use whichever recovery tool is configured. REA never downloads, installs, or updates it`;

/** Remediation for malformed tool output. */
export const PROTOBUF_OUTPUT_REMEDIATION = `Confirm the selected tool writes .proto files for this artifact. REA parses recovered definitions and reports no partial success when none are recognized`;

/**
 * pbtk, protodump, and grpcurl argument/output shapes are documented
 * assumptions. No verified release of any of the three tools is pinned.
 */
export const PROTOBUF_LANE_UNVERIFIED_NOTE =
  "The pbtk, protodump, and grpcurl shapes in this lane are documented assumptions; no verified release of any of the three tools is pinned yet.";
