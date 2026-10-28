import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import { LabVmSessionManager } from "../vmlab/LabVmSessionManager.js";

/** Compose the Lima lab-VM lane without import-time I/O or dependency acquisition. */
export const createLabVmService = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): LabVmPort => new LabVmSessionManager({ environment });
