import type { CapaAnalysisPort } from "../application/capa/CapaAnalysisPort.js";
import { CapaProvider } from "../capa/CapaProvider.js";

/** Construct one capa provider over the caller-supplied capa binary. */
export const createCapaAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): CapaAnalysisPort => new CapaProvider({ environment });
