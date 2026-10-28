import { isIP } from "node:net";
import { z } from "zod";

import type { JsonValue } from "../jsonValue.js";
import { err, ok, type Result } from "../result.js";
import {
  PROTOLEARN_LAB_ENDPOINTS_ENV,
  PROTOLEARN_LAB_ENDPOINTS_REMEDIATION,
  PROTOLEARN_LIMITS,
} from "./protolearnLimits.js";

/** Destinations the kernel's sandbox profile grammar can name exactly. */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

/**
 * Whether this destination is loopback. The deny-default profile names only
 * `localhost`, so a probe to another address cannot be confined and is refused
 * rather than run unconfined.
 */
export const isLoopbackLabHost = (host: string): boolean =>
  LOOPBACK_HOSTS.has(host);

export type ProtolearnConfigurationFailureCode =
  | "not_configured"
  | "invalid_encoding"
  | "invalid_endpoint"
  | "endpoint_not_allowlisted";

/**
 * A probe-lane configuration refusal. `diagnostics.remediation` is the
 * operator action, so `providerConfigurationRefusal` can carry it unchanged.
 */
export class ProtolearnConfigurationFailure extends Error {
  constructor(
    readonly code: ProtolearnConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ProtolearnConfigurationFailure";
  }
}

/** One lab socket literal: an IP literal and a port, never a hostname. */
export interface LabEndpoint {
  readonly host: string;
  readonly port: number;
  /** Canonical `host:port` spelling the operator allowlist stores. */
  readonly literal: string;
}

const portText = (value: string): number | undefined => {
  if (!/^[1-9][0-9]{0,4}$/u.test(value)) return undefined;
  const port = Number(value);
  return port <= 65_535 ? port : undefined;
};

/**
 * Canonicalize one `host:port` literal. A name is refused because the sandbox
 * profile matches kernel addresses, so an unresolved name would silently widen
 * or fail the declared destination.
 */
export const normalizedLabEndpoint = (
  value: string,
): LabEndpoint | undefined => {
  const trimmed = value.trim();
  const bracketed = /^\[([^\]]+)\]:([0-9]+)$/u.exec(trimmed);
  const plain = bracketed === null ? /^([^:[\]]+):([0-9]+)$/u.exec(trimmed) : null;
  const match = bracketed ?? plain;
  if (match === null) return undefined;
  const host = match[1];
  const portTextValue = match[2];
  if (host === undefined || portTextValue === undefined) return undefined;
  const port = portText(portTextValue);
  if (port === undefined) return undefined;
  if (isIP(host) === 0) return undefined;
  return { host, port, literal: `${host}:${String(port)}` };
};

/**
 * Parse the operator allowlist. A malformed or empty setting disables the
 * probe lane rather than being read as "allow everything".
 */
export const parseProtolearnLabEndpoints = (
  encoded: string | undefined,
): Result<readonly LabEndpoint[], ProtolearnConfigurationFailure> => {
  const remediation = PROTOLEARN_LAB_ENDPOINTS_REMEDIATION;
  if (encoded === undefined || encoded.trim() === "")
    return err(
      new ProtolearnConfigurationFailure(
        "not_configured",
        `The learned-model probe lane is disabled because ${PROTOLEARN_LAB_ENDPOINTS_ENV} is unset`,
        { setting: PROTOLEARN_LAB_ENDPOINTS_ENV, remediation },
      ),
    );
  let decoded: unknown;
  try {
    decoded = JSON.parse(encoded);
  } catch (cause: unknown) {
    return err(
      new ProtolearnConfigurationFailure(
        "invalid_encoding",
        `${PROTOLEARN_LAB_ENDPOINTS_ENV} must be a JSON array of host:port literals`,
        { setting: PROTOLEARN_LAB_ENDPOINTS_ENV, remediation },
        { cause },
      ),
    );
  }
  const parsed = z.array(z.string().min(1)).safeParse(decoded);
  if (!parsed.success)
    return err(
      new ProtolearnConfigurationFailure(
        "invalid_encoding",
        `${PROTOLEARN_LAB_ENDPOINTS_ENV} must be a JSON array of host:port literals`,
        { setting: PROTOLEARN_LAB_ENDPOINTS_ENV, remediation },
        { cause: parsed.error },
      ),
    );
  if (parsed.data.length > PROTOLEARN_LIMITS.maxProbeLabels * 8)
    return err(
      new ProtolearnConfigurationFailure(
        "invalid_encoding",
        `${PROTOLEARN_LAB_ENDPOINTS_ENV} lists more endpoints than this lane admits`,
        {
          setting: PROTOLEARN_LAB_ENDPOINTS_ENV,
          entry_count: parsed.data.length,
          remediation,
        },
      ),
    );
  const endpoints: LabEndpoint[] = [];
  for (const [index, value] of parsed.data.entries()) {
    const endpoint = normalizedLabEndpoint(value);
    if (endpoint === undefined)
      return err(
        new ProtolearnConfigurationFailure(
          "invalid_endpoint",
          `${PROTOLEARN_LAB_ENDPOINTS_ENV}[${String(index)}] must be an IPv4 or IPv6 literal and a port; a hostname cannot be expressed in the sandbox profile`,
          {
            setting: PROTOLEARN_LAB_ENDPOINTS_ENV,
            entry: index,
            remediation,
          },
        ),
      );
    if (!endpoints.some(({ literal }) => literal === endpoint.literal))
      endpoints.push(endpoint);
  }
  if (endpoints.length === 0)
    return err(
      new ProtolearnConfigurationFailure(
        "not_configured",
        `The learned-model probe lane is disabled because ${PROTOLEARN_LAB_ENDPOINTS_ENV} lists no endpoints`,
        { setting: PROTOLEARN_LAB_ENDPOINTS_ENV, remediation },
      ),
    );
  return ok(endpoints);
};

/**
 * Approve one declared endpoint for this request. Both the operator setting
 * and the request must name it exactly; matching is on the canonical literal,
 * so `127.0.0.1:9000` never approves a different port or address family.
 */
export const labEndpointApproval = (
  declared: { readonly host: string; readonly port: number },
  allowed: readonly LabEndpoint[],
):
  | { readonly approved: true; readonly endpoint: LabEndpoint }
  | { readonly approved: false; readonly reason: string } => {
  if (isIP(declared.host) === 0)
    return {
      approved: false,
      reason:
        "the declared lab endpoint host must be an IPv4 or IPv6 literal; the sandbox profile matches kernel addresses, so a name cannot be expressed",
    };
  const literal = `${declared.host}:${String(declared.port)}`;
  const endpoint = allowed.find((entry) => entry.literal === literal);
  return endpoint === undefined
    ? {
        approved: false,
        reason: `the declared lab endpoint ${literal} is not in ${PROTOLEARN_LAB_ENDPOINTS_ENV}`,
      }
    : { approved: true, endpoint };
};
