import { LiefService } from "../application/lief/LiefService.js";
import { LiefDeepProvider } from "../lief/LiefDeepProvider.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";

/**
 * Compose the LIEF deep-parse lane over the caller-selected interpreter and
 * bridge script. Nothing here installs LIEF; the lane refuses typed until the
 * caller supplies both.
 */
export const createLiefService = (
  selectedEnvironment: Readonly<NodeJS.ProcessEnv>,
): LiefService =>
  new LiefService(
    new LiefDeepProvider(snapshotEnvironment(selectedEnvironment)),
  );
