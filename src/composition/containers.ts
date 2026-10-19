import { ContainerInspectionService } from "../application/containers/ContainerInspectionService.js";

/** Compose bundled offline container inspection: no processes, no network. */
export const createContainerInspectionService =
  (): ContainerInspectionService => new ContainerInspectionService();
