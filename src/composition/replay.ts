import type { ReplayPort } from "../application/replay/ReplayPort.js";
import {
  REPLAY_ALLOWED_ORIGINS_ENV,
  parseReplayAllowedOrigins,
} from "../domain/replay/replayOrigins.js";
import { ReplayService } from "../replay/ReplayService.js";

/** Compose the active request plane without import-time I/O or dispatch. */
export const createReplayService = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): ReplayPort => new ReplayService({ environment });

/**
 * Whether an operator has approved at least one origin. An unset, empty,
 * malformed, or entirely rejected allowlist leaves the plane disabled; REA
 * never enables it from a request alone.
 */
export const replayAllowedOriginsConfigured = (
  environment: Readonly<Record<string, string | undefined>>,
): boolean =>
  parseReplayAllowedOrigins(environment[REPLAY_ALLOWED_ORIGINS_ENV]).ok;
