import {
  LAB_VM_GUEST_WORKSPACE,
  LAB_VM_ROSETTA_ENABLED,
  LAB_VM_DRIVER,
} from "./labVm.js";

/** Why a template could not be rendered for the selected workspace. */
export class LabVmTemplateRejection extends Error {
  readonly _tag = "LabVmTemplateRejection";
  constructor(message: string) {
    super(message);
    this.name = "LabVmTemplateRejection";
  }
}

/**
 * Render one double-quoted YAML scalar.
 *
 * YAML double-quoted scalars share JSON's escapes for the characters that
 * matter here, so `JSON.stringify` is the exact representable form. Control
 * characters other than tab and newline are rejected rather than encoded,
 * because a workspace path never legitimately contains them.
 */
const scalar = (value: string, field: string): string => {
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value))
    throw new LabVmTemplateRejection(
      `${field} contains a control character that a Lima mount location cannot represent: ${JSON.stringify(value)}`,
    );
  return JSON.stringify(value);
};

/**
 * The Lima template REA writes for one lab VM.
 *
 * The caller's workspace is the only host directory mounted, and it is mounted
 * writable at `/workspace`, so every artifact the guest produces is visible to
 * the caller after the VM stops.
 */
export const labVmTemplate = (workspacePath: string): string =>
  [
    "# REA lab VM template; generated per start and deleted with the session.",
    `vmType: ${LAB_VM_DRIVER}`,
    "rosetta:",
    `  enabled: ${String(LAB_VM_ROSETTA_ENABLED)}`,
    "  binfmt: true",
    "mounts:",
    `  - location: ${scalar(workspacePath, "workspace_path")}`,
    `    mountPoint: ${scalar(LAB_VM_GUEST_WORKSPACE, "guest workspace")}`,
    "    writable: true",
    "",
  ].join("\n");
