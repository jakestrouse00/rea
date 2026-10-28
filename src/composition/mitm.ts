import type { MitmInterceptionPort } from "../application/mitm/MitmInterceptionPort.js";
import { MitmSessionManager } from "../mitm/MitmSessionManager.js";
import { mitmInterceptionConfigured } from "../mitm/MitmConfiguration.js";

/** Compose the interception lane without import-time I/O or dispatch. */
export const createMitmInterceptionService = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): MitmInterceptionPort => new MitmSessionManager({ environment });

/** Whether a mitmdump binary and generated addon are both selected. */
export const mitmInterceptionLaneEnabled = (
  environment: Readonly<Record<string, string | undefined>>,
  provided: boolean,
): boolean => provided || mitmInterceptionConfigured(environment);
