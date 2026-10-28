import type { EmuAnalysisPort } from "../application/emu/EmuAnalysisPort.js";
import { EmuProvider } from "../emu/EmuProvider.js";
import { emuLaneConfigured } from "../emu/EmuConfiguration.js";

/** Construct the emulation lane over the caller-managed sidecar environment. */
export const createEmuAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): EmuAnalysisPort => new EmuProvider({ environment });

/** Whether an interpreter and bridge script are both selected. */
export const emuLaneEnabled = (
  environment: Readonly<Record<string, string | undefined>>,
  provided: boolean,
): boolean => provided || emuLaneConfigured(environment);
