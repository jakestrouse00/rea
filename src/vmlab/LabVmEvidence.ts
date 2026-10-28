import { createEvidence, type Evidence } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  LAB_VM_GUEST_ARCHITECTURE,
  LAB_VM_PROVIDER,
} from "../domain/vmlab/labVm.js";
import {
  labVmCommandResultSchema,
  labVmStartResultSchema,
  labVmStopResultSchema,
} from "../domain/vmlab/labVmObservation.js";

const environment = {
  id: `lima-vz-${LAB_VM_GUEST_ARCHITECTURE}`,
  platform: "linux",
  architecture: LAB_VM_GUEST_ARCHITECTURE,
  isolation: "virtual-machine",
} as const;

const locationOf = (workspacePath: string, relative: string) => ({
  kind: "artifact-path" as const,
  path: `${workspacePath.replace(/\/+$/u, "")}/${relative}`,
});

/** Evidence for one observed lab VM boot. */
export const createLabVmStartEvidence = (
  parameters: Readonly<Record<string, JsonValue>>,
  result: unknown,
  limitations: readonly string[],
): Evidence =>
  createEvidence(undefined, LAB_VM_PROVIDER, {
    predicateType: "lab-vm-lifecycle",
    operation: "start_lab_vm",
    parameters,
    result: labVmStartResultSchema.parse(result),
    confidence: "observed",
    authority: "controlled-replay",
    environment,
    limitations,
    locations: [],
  });

/** Evidence for one guest command, with the paths it produced as locations. */
export const createLabVmCommandEvidence = (
  parameters: Readonly<Record<string, JsonValue>>,
  workspacePath: string,
  result: unknown,
  limitations: readonly string[],
): Evidence => {
  const parsed = labVmCommandResultSchema.parse(result);
  return createEvidence(undefined, LAB_VM_PROVIDER, {
    predicateType: "lab-vm-command",
    operation: "run_lab_vm_command",
    parameters,
    result: parsed,
    confidence: "observed",
    authority: "controlled-replay",
    environment,
    limitations,
    locations: [
      ...new Set([...parsed.produced_paths, ...parsed.modified_paths]),
    ]
      .sort()
      .map((relative) => locationOf(workspacePath, relative)),
  });
};

/** Evidence for one observed stop and removal. */
export const createLabVmStopEvidence = (
  parameters: Readonly<Record<string, JsonValue>>,
  result: unknown,
  limitations: readonly string[],
): Evidence =>
  createEvidence(undefined, LAB_VM_PROVIDER, {
    predicateType: "lab-vm-lifecycle",
    operation: "stop_lab_vm",
    parameters,
    result: labVmStopResultSchema.parse(result),
    confidence: "observed",
    authority: "controlled-replay",
    environment,
    limitations,
    locations: [],
  });
