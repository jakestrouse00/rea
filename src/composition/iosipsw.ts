import type { IpswAnalysisPort } from "../application/iosipsw/IpswAnalysisPort.js";
import { IpswProvider } from "../iosipsw/IpswProvider.js";

/** Construct one iosipsw provider over the caller-supplied ipsw binary. */
export const createIpswAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): IpswAnalysisPort => new IpswProvider({ environment });
