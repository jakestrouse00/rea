/** Stable provider ID shared by readiness, doctor and Evidence. */
export const PDB_PROVIDER_ID = "llvm-pdbutil";

/** Remediation when `REA_LLVM_PDBUTIL_COMMAND` is missing or not absolute. */
export const PDB_COMMAND_REMEDIATION = `Set REA_LLVM_PDBUTIL_COMMAND to the absolute path of a caller-supplied llvm-pdbutil executable (BYO LLVM tooling). REA does not download, install or update llvm-pdbutil.`;

/** Remediation when the configured executable's --version cannot be read. */
export const PDB_VERSION_PROBE_REMEDIATION =
  "Run the configured executable with --version: it must exit promptly and print an LLVM version banner.";

/** Remediation for a failed `llvm-pdbutil dump` run. */
export const PDB_DUMP_REMEDIATION =
  "Run the same `llvm-pdbutil dump -summary -streams -modules -files -symbols -publics` command on the selected PDB and inspect its stderr directly.";
