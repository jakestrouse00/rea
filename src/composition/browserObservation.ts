import type { BrowserObservationPort } from "../application/BrowserObservationPort.js";
import { CdpBrowserProvider } from "../browser/CdpBrowserProvider.js";
import {
  REPLAY_ALLOWED_ORIGINS_ENV,
  parseReplayAllowedOrigins,
} from "../domain/replay/replayOrigins.js";

/**
 * Operator-approved origins for page-context dispatch.
 *
 * The same allowlist governs the active request plane. An unset or malformed
 * setting leaves the mutation lane disabled instead of widening it.
 */
export const browserMutationOrigins = (
  environment: Readonly<Record<string, string | undefined>>,
): readonly string[] => {
  const parsed = parseReplayAllowedOrigins(
    environment[REPLAY_ALLOWED_ORIGINS_ENV],
  );
  return parsed.ok ? parsed.value : [];
};

/** Construct a fresh provider without opening a target or acquiring an engine. */
export const createBrowserObservationProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): BrowserObservationPort =>
  new CdpBrowserProvider({
    mutationOrigins: browserMutationOrigins(environment),
  });
