import type { DiscoveryAnalysisPort } from "../application/discovery/DiscoveryPort.js";
import { DiscoveryProvider } from "../discovery/DiscoveryProvider.js";

/** Construct one discovery provider over macOS host-provided tools. */
export const createDiscoveryAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): DiscoveryAnalysisPort => new DiscoveryProvider({ environment });
