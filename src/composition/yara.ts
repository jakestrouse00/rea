import type { YaraAnalysisPort } from "../application/yara/YaraAnalysisPort.js";
import { YaraProvider } from "../yara/YaraProvider.js";

/** Construct one YARA-X provider over the caller-supplied `yr` binary. */
export const createYaraAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): YaraAnalysisPort => new YaraProvider({ environment });
