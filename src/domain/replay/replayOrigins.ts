import { z } from "zod";

import type { JsonValue } from "../jsonValue.js";
import { err, ok, type Result } from "../result.js";

/** Operator allowlist for the active request plane; unset means disabled. */
export const REPLAY_ALLOWED_ORIGINS_ENV = "REA_REPLAY_ALLOWED_ORIGINS";

/** Provider identity reported by the active request plane. */
export const REPLAY_PROVIDER_ID = "rea-replay";
export const REPLAY_PROVIDER = {
  id: REPLAY_PROVIDER_ID,
  name: "REA HTTP replay client",
  version: "1",
} as const;

export type ReplayConfigurationFailureCode =
  | "not_configured"
  | "invalid_encoding"
  | "invalid_origin"
  | "origin_not_allowlisted";

/**
 * A request-plane configuration refusal. `diagnostics.remediation` is the
 * operator action, so `providerConfigurationRefusal` can carry it unchanged.
 */
export class ReplayConfigurationFailure extends Error {
  constructor(
    readonly code: ReplayConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ReplayConfigurationFailure";
  }
}

/** Operator remediation for every default-disabled refusal. */
export const REPLAY_ALLOWED_ORIGINS_REMEDIATION = `Set ${REPLAY_ALLOWED_ORIGINS_ENV} to a JSON array of exact http or https origins (for example ["https://api.example.test"]) in the REA launch environment, restart REA, then declare those origins again in http_replay_session_start. REA never enables the request plane or approves an origin on its own.`;

const originSchema = z.string().min(1);

/**
 * Parse the operator allowlist. Origins are exact scheme/host/port triples:
 * a path, query, fragment, userinfo, or wildcard makes the whole setting
 * unusable rather than being silently dropped.
 */
export const parseReplayAllowedOrigins = (
  encoded: string | undefined,
): Result<readonly string[], ReplayConfigurationFailure> => {
  if (encoded === undefined || encoded.trim() === "")
    return err(
      new ReplayConfigurationFailure(
        "not_configured",
        `The active request plane is disabled because ${REPLAY_ALLOWED_ORIGINS_ENV} is unset`,
        {
          setting: REPLAY_ALLOWED_ORIGINS_ENV,
          remediation: REPLAY_ALLOWED_ORIGINS_REMEDIATION,
        },
      ),
    );
  let decoded: unknown;
  try {
    decoded = JSON.parse(encoded);
  } catch (cause: unknown) {
    return err(
      new ReplayConfigurationFailure(
        "invalid_encoding",
        `${REPLAY_ALLOWED_ORIGINS_ENV} must be a JSON array of origins`,
        {
          setting: REPLAY_ALLOWED_ORIGINS_ENV,
          remediation: REPLAY_ALLOWED_ORIGINS_REMEDIATION,
        },
        { cause },
      ),
    );
  }
  const parsed = z.array(originSchema).safeParse(decoded);
  if (!parsed.success)
    return err(
      new ReplayConfigurationFailure(
        "invalid_encoding",
        `${REPLAY_ALLOWED_ORIGINS_ENV} must be a JSON array of origins`,
        {
          setting: REPLAY_ALLOWED_ORIGINS_ENV,
          remediation: REPLAY_ALLOWED_ORIGINS_REMEDIATION,
        },
        { cause: parsed.error },
      ),
    );
  const origins: string[] = [];
  for (const [index, value] of parsed.data.entries()) {
    const origin = normalizedReplayOrigin(value);
    if (origin === undefined)
      return err(
        new ReplayConfigurationFailure(
          "invalid_origin",
          `${REPLAY_ALLOWED_ORIGINS_ENV}[${String(index)}] is not an exact http or https origin`,
          {
            setting: REPLAY_ALLOWED_ORIGINS_ENV,
            entry: index,
            remediation: REPLAY_ALLOWED_ORIGINS_REMEDIATION,
          },
        ),
      );
    if (!origins.includes(origin)) origins.push(origin);
  }
  if (origins.length === 0)
    return err(
      new ReplayConfigurationFailure(
        "not_configured",
        `The active request plane is disabled because ${REPLAY_ALLOWED_ORIGINS_ENV} lists no origins`,
        {
          setting: REPLAY_ALLOWED_ORIGINS_ENV,
          remediation: REPLAY_ALLOWED_ORIGINS_REMEDIATION,
        },
      ),
    );
  return ok(origins);
};

/** Canonical origin for an exact scheme/host/port triple, else undefined. */
export const normalizedReplayOrigin = (value: string): string | undefined => {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause: unknown) {
    void cause;
    return undefined;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:")
    return undefined;
  if (parsed.username !== "" || parsed.password !== "") return undefined;
  if (parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "")
    return undefined;
  // `URL.origin` lowercases the host and drops the default port. A value that
  // does not round-trip still names a real origin; normalization is reported
  // through the returned triple rather than rejecting the entry.
  return parsed.origin;
};

/**
 * Approve one absolute request URL for the operator allowlist. Userinfo is
 * refused outright: credentials belong in headers, and an echoed URL is a
 * credential leak the request plane will not create.
 */
export const replayUrlApproval = (
  value: string,
  allowedOrigins: readonly string[],
):
  | { readonly approved: true; readonly url: string; readonly origin: string }
  | { readonly approved: false; readonly reason: string } => {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause: unknown) {
    void cause;
    return {
      approved: false,
      reason: "the request URL is not an absolute URL",
    };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:")
    return {
      approved: false,
      reason: "only http and https request URLs are replayed",
    };
  if (parsed.username !== "" || parsed.password !== "")
    return {
      approved: false,
      reason:
        "the request URL carries userinfo; replay credentials belong in headers",
    };
  if (!allowedOrigins.includes(parsed.origin))
    return {
      approved: false,
      reason: `the request origin ${parsed.origin} is outside this session's approved origins`,
    };
  return { approved: true, url: parsed.href, origin: parsed.origin };
};

/** Normalize one declared session origin, reusing the operator grammar. */
export const replayDeclaredOrigin = (value: string): string | undefined =>
  normalizedReplayOrigin(value);
