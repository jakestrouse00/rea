/** Stable provider identity and caller-facing remediation for Python source recovery. */
export const PYTHON_DECOMPILER_PROVIDER_ID = "python-decompiler";

/** Provider name used in Evidence provenance. */
export const PYTHON_DECOMPILER_PROVIDER_NAME =
  "Python bytecode decompilation (PyLingual or pycdc)";

/** Environment key selecting a PyLingual CLI. Tried first when both are set. */
export const PYLINGUAL_COMMAND_ENV = "REA_PYLINGUAL_COMMAND";

/** Environment key selecting a pycdc executable. */
export const PYCDC_COMMAND_ENV = "REA_PYCDC_COMMAND";

/** Remediation for an unset or unusable Python decompiler selection. */
export const PYTHON_DECOMPILER_REMEDIATION = `Install PyLingual or pycdc for this host and point ${PYLINGUAL_COMMAND_ENV} or ${PYCDC_COMMAND_ENV} at an absolute path to the executable. REA never downloads, installs, or updates it`;

/** Remediation for malformed output rather than a missing tool. */
export const PYTHON_DECOMPILER_OUTPUT_REMEDIATION = `Confirm the selected Python decompiler prints recovered source for a .pyc file. REA parses declarations only and reports no partial success when no declaration is recognized`;

/**
 * PyLingual and pycdc CLI shapes are documented assumptions. No verified
 * release of either tool is pinned; every result carries this note.
 */
export const PYTHON_LANE_UNVERIFIED_NOTE =
  "The PyLingual and pycdc output shapes in this lane are documented assumptions; no verified release of either tool is pinned yet.";
