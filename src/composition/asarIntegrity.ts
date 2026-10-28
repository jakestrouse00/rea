import type { AsarIntegrityPort } from "../application/electron/AsarIntegrityPort.js";
import { AsarIntegrityProvider } from "../electron/AsarIntegrityProvider.js";

/** Construct one ASAR integrity reader over the selected header admission. */
export const createAsarIntegrityProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): AsarIntegrityPort => new AsarIntegrityProvider(environment);
