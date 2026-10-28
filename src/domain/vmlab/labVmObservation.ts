import { z } from "zod";

import {
  LAB_VM_DRIVER,
  LAB_VM_GUEST_WORKSPACE,
  labVmExitTypeSchema,
} from "./labVm.js";

/** One observed limactl call: how it ended and how long it ran. */
export const labVmCallSchema = z.strictObject({
  exit_type: labVmExitTypeSchema.describe(
    "exited: limactl reported an exit status. signalled: limactl ended on a signal without a status. timeout: REA stopped it at its deadline. cancelled: the caller cancelled the operation.",
  ),
  exit_code: z
    .int()
    .nullable()
    .describe("Reported exit status, or null when limactl ended on a signal."),
  duration_ms: z.int().min(0),
});

export type LabVmCall = z.infer<typeof labVmCallSchema>;

/** One started lab VM with the observed boot call. */
export const labVmStartResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  vm_name: z.string().min(1),
  workspace_path: z
    .string()
    .min(1)
    .describe("Host directory mounted read-write in the guest."),
  guest_workspace: z.literal(LAB_VM_GUEST_WORKSPACE),
  driver: z.literal(LAB_VM_DRIVER),
  rosetta: z.literal(true),
  boot: labVmCallSchema,
});

/** Structural outcome of one guest command; no raw output is retained here. */
export const labVmCommandResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  command: z.string().min(1),
  exit_type: labVmExitTypeSchema,
  exit_code: z.int().nullable(),
  duration_ms: z.int().min(0),
  timeout_ms: z.int().min(1),
  stdout_bytes: z.int().min(0),
  stderr_bytes: z.int().min(0),
  output_truncated: z.boolean(),
  produced_paths: z
    .array(z.string().min(1))
    .describe(
      "Workspace-relative paths that did not exist before this command and exist after it.",
    ),
  modified_paths: z
    .array(z.string().min(1))
    .describe(
      "Workspace-relative paths whose size or modification time changed during this command.",
    ),
  removed_paths: z
    .array(z.string().min(1))
    .describe(
      "Workspace-relative paths present before this command and absent after it.",
    ),
  changes_truncated: z
    .boolean()
    .describe(
      "A bounded workspace inventory or change list stopped before it covered the workspace.",
    ),
});

export type LabVmCommandResult = z.infer<typeof labVmCommandResultSchema>;

/** Observed stop and removal of one lab VM. */
export const labVmStopResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  vm_name: z.string().min(1),
  stop: labVmCallSchema
    .nullable()
    .describe(
      "The stop call observed by this request, or null when a retry only removed an instance whose stop observation was already retained.",
    ),
  deleted: z
    .boolean()
    .describe(
      "Whether the instance and its guest disk were removed after the stop.",
    ),
});
