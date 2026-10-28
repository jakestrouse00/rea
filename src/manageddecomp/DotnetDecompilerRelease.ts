/** Stable provider identity and caller-facing remediation for the .NET lane. */
export const DOTNET_DECOMPILER_PROVIDER_ID = "ilspycmd";

/** Provider name used in Evidence provenance. */
export const DOTNET_DECOMPILER_PROVIDER_NAME = "ilspycmd (.NET decompilation)";

/** Environment key selecting the caller's ilspycmd executable. */
export const ILSPY_COMMAND_ENV = "REA_ILSPY_CMD_PATH";

/** Remediation for an unset or unusable ilspycmd selection. */
export const ILSPY_COMMAND_REMEDIATION = `Install ilspycmd for this host (dotnet tool install -g ilspycmd) or point ${ILSPY_COMMAND_ENV} at an absolute path to an existing ilspycmd executable. REA never downloads, installs, or updates it`;

/** Remediation for malformed ilspycmd output rather than a missing tool. */
export const ILSPY_VERSION_PROBE_REMEDIATION = `Confirm the selected ${ILSPY_COMMAND_ENV} binary answers \`ilspycmd --version\`. REA records no version when the probe cannot recognize its output`;

/**
 * The decompiled C# shape is parsed structurally. No verified ilspycmd release
 * is pinned; every result carries this note.
 */
export const DOTNET_LANE_UNVERIFIED_NOTE =
  "The ilspycmd output shape in this lane is a documented assumption; no verified ilspycmd release is pinned yet.";
