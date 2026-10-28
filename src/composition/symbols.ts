import type { SymbolRecoveryPort } from "../application/symbols/SymbolRecoveryPort.js";
import { SymbolRecoveryProvider } from "../symbolrecovery/SymbolRecoveryProvider.js";

/** Construct one symbol-recovery provider over the caller's toolchain. */
export const createSymbolRecoveryProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): SymbolRecoveryPort => new SymbolRecoveryProvider({ environment });
