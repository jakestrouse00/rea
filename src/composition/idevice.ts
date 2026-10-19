import type { IdeviceAnalysisPort } from "../application/idevice/IdevicePort.js";
import { IdeviceProvider } from "../idevice/IdeviceProvider.js";

/** Construct one iOS device-read provider over caller-supplied pymobiledevice3. */
export const createIdeviceAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): IdeviceAnalysisPort => new IdeviceProvider({ environment });
