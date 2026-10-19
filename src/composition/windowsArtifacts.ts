import { WindowsArtifactsService } from "../application/windowsArtifacts/WindowsArtifactsService.js";
import { PdbSymbolProvider } from "../pdb/PdbSymbolProvider.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { WindowsMinidumpProvider } from "../windows/WindowsMinidumpProvider.js";
import { WindowsWerProvider } from "../windows/WindowsWerProvider.js";

/**
 * Compose the bundled offline Windows-artifact readers plus the BYO
 * llvm-pdbutil lane. No target execution; the PDB lane launches only the
 * caller-configured llvm-pdbutil executable.
 */
export const createWindowsArtifactsService = (
  selectedEnvironment: Readonly<NodeJS.ProcessEnv>,
): WindowsArtifactsService => {
  const environment = snapshotEnvironment(selectedEnvironment);
  return new WindowsArtifactsService(
    new WindowsMinidumpProvider(),
    new WindowsWerProvider(),
    new PdbSymbolProvider(environment),
  );
};
