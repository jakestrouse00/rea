import type { EvidenceProvider } from "../evidence.js";

/** Provider identity shared by the container inspection operations. */
export const CONTAINER_PROVIDER_IDENTITY = {
  id: "containers",
  name: "REA container inspector",
  version: null,
} as const;
