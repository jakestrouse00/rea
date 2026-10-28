import type {
  MitmBodyHold,
  MitmFlowEvent,
  MitmShapeSketch,
} from "./mitmStream.js";
import {
  MITM_LIMITS,
  MITM_PARAMETER_LOCATIONS,
  type MitmParameterLocation,
  type MitmParameterType,
} from "./mitmLimits.js";
import {
  REPLAY_STATUS_CLASSES,
  replayStatusClass,
} from "../replay/replayLimits.js";

/** One parameter name an endpoint accepts, with the types observed for it. */
export interface MitmParameterSummary {
  readonly name: string;
  readonly location: MitmParameterLocation;
  readonly types: readonly MitmParameterType[];
}

/** One status observed on an endpoint, with how often it occurred. */
export interface MitmStatusCount {
  readonly status: number;
  readonly status_class: (typeof REPLAY_STATUS_CLASSES)[number];
  readonly count: number;
}

/** Everything retained about one method/template pair on one origin. */
export interface MitmEndpointFacts {
  readonly origin: string;
  readonly method: string;
  readonly path_template: string;
  readonly occurrences: number;
  readonly first_at: string;
  readonly last_at: string;
  readonly status_histogram: readonly MitmStatusCount[];
  readonly request_header_names: readonly string[];
  readonly response_header_names: readonly string[];
  readonly parameters: readonly MitmParameterSummary[];
  readonly response_shape: MitmShapeSketch | null;
  /** How many distinct response shapes were seen after the first one. */
  readonly shape_variants: number;
}

/** Session-wide capture totals; omissions stay explicit. */
export interface MitmInventoryTotals {
  readonly flows: number;
  readonly endpoints: number;
  readonly endpoints_omitted: number;
  readonly facts_omitted: number;
  readonly requests_without_response: number;
  readonly bodies_held: number;
  readonly body_bytes_held: number;
}

export interface MitmInventorySnapshot {
  readonly totals: MitmInventoryTotals;
  readonly endpoints: readonly MitmEndpointFacts[];
}

interface MutableEndpoint {
  readonly origin: string;
  readonly method: string;
  readonly pathTemplate: string;
  occurrences: number;
  firstAt: string;
  lastAt: string;
  readonly statuses: Map<number, number>;
  readonly requestHeaderNames: Set<string>;
  readonly responseHeaderNames: Set<string>;
  readonly parameters: Map<string, { types: Set<MitmParameterType> }>;
  shape: MitmShapeSketch | null;
  shapeKey: string | null;
  shapeVariants: number;
}

const endpointKey = (origin: string, method: string, pathTemplate: string) =>
  `${origin}\u0000${method}\u0000${pathTemplate}`;

const parameterKey = (location: MitmParameterLocation, name: string) =>
  `${location}\u0000${name}`;

const parameterOrder = (
  left: MitmParameterSummary,
  right: MitmParameterSummary,
) => {
  const byLocation =
    MITM_PARAMETER_LOCATIONS.indexOf(left.location) -
    MITM_PARAMETER_LOCATIONS.indexOf(right.location);
  return byLocation === 0
    ? left.name < right.name
      ? -1
      : left.name > right.name
        ? 1
        : 0
    : byLocation;
};

const bodyByteCount = (hold: MitmBodyHold | null): number =>
  hold === null ? 0 : hold.bytes;

/**
 * Bounded, value-free endpoint inventory built from the structure stream.
 *
 * Every fact here came from the addon as a name, a type, or a count. The
 * reducer enforces the per-session endpoint, parameter, status, and header-name
 * budgets and reports what it omitted instead of dropping silently.
 */
export class MitmInventory {
  readonly #endpoints = new Map<string, MutableEndpoint>();
  #flows = 0;
  #endpointsOmitted = 0;
  #factsOmitted = 0;
  #withoutResponse = 0;
  #bodiesHeld = 0;
  #bodyBytesHeld = 0;

  applyFlow(event: MitmFlowEvent): void {
    this.#flows += 1;
    const { request } = event;
    const key = endpointKey(
      request.origin,
      request.method,
      request.path_template,
    );
    let endpoint = this.#endpoints.get(key);
    if (endpoint === undefined) {
      if (this.#endpoints.size >= MITM_LIMITS.maxEndpoints) {
        this.#endpointsOmitted += 1;
        return;
      }
      endpoint = {
        origin: request.origin,
        method: request.method,
        pathTemplate: request.path_template,
        occurrences: 0,
        firstAt: event.at,
        lastAt: event.at,
        statuses: new Map(),
        requestHeaderNames: new Set(),
        responseHeaderNames: new Set(),
        parameters: new Map(),
        shape: null,
        shapeKey: null,
        shapeVariants: 0,
      };
      this.#endpoints.set(key, endpoint);
    }
    endpoint.occurrences += 1;
    endpoint.lastAt = event.at;
    for (const name of request.header_names)
      this.#addName(endpoint.requestHeaderNames, name);
    for (const parameter of request.parameters) {
      const id = parameterKey(parameter.location, parameter.name);
      let entry = endpoint.parameters.get(id);
      if (entry === undefined) {
        if (endpoint.parameters.size >= MITM_LIMITS.maxParametersPerEndpoint) {
          this.#factsOmitted += 1;
          continue;
        }
        entry = { types: new Set() };
        endpoint.parameters.set(id, entry);
      }
      if (
        !entry.types.has(parameter.type) &&
        entry.types.size < MITM_LIMITS.maxParameterTypes
      )
        entry.types.add(parameter.type);
      else if (!entry.types.has(parameter.type)) this.#factsOmitted += 1;
    }
    const response = event.response;
    if (response === null) {
      this.#withoutResponse += 1;
    } else {
      if (response.body_hold !== null) this.#bodiesHeld += 1;
      this.#bodyBytesHeld += bodyByteCount(response.body_hold);
      const seen = endpoint.statuses.get(response.status) ?? 0;
      if (seen > 0) endpoint.statuses.set(response.status, seen + 1);
      else if (endpoint.statuses.size >= MITM_LIMITS.maxStatusCodes)
        this.#factsOmitted += 1;
      else endpoint.statuses.set(response.status, 1);
      for (const name of response.header_names)
        this.#addName(endpoint.responseHeaderNames, name);
      if (response.shape !== null) {
        const shapeKey = JSON.stringify(response.shape);
        if (endpoint.shapeKey === null) {
          endpoint.shape = response.shape;
          endpoint.shapeKey = shapeKey;
        } else if (endpoint.shapeKey !== shapeKey) endpoint.shapeVariants += 1;
      }
    }
    if (request.body_hold !== null) {
      this.#bodiesHeld += 1;
      this.#bodyBytesHeld += request.body_hold.bytes;
    }
  }

  #addName(names: Set<string>, name: string): void {
    if (names.has(name)) return;
    if (names.size >= MITM_LIMITS.maxHeaderNames) this.#factsOmitted += 1;
    else names.add(name);
  }

  /** Deterministic order: origin, then path template, then method. */
  snapshot(): MitmInventorySnapshot {
    const endpoints = [...this.#endpoints.values()]
      .sort((left, right) => {
        if (left.origin !== right.origin)
          return left.origin < right.origin ? -1 : 1;
        if (left.pathTemplate !== right.pathTemplate)
          return left.pathTemplate < right.pathTemplate ? -1 : 1;
        return left.method < right.method
          ? -1
          : left.method > right.method
            ? 1
            : 0;
      })
      .map((endpoint): MitmEndpointFacts => ({
        origin: endpoint.origin,
        method: endpoint.method,
        path_template: endpoint.pathTemplate,
        occurrences: endpoint.occurrences,
        first_at: endpoint.firstAt,
        last_at: endpoint.lastAt,
        status_histogram: [...endpoint.statuses.entries()]
          .map(([status, count]) => ({
            status,
            status_class: replayStatusClass(status),
            count,
          }))
          .sort((left, right) => left.status - right.status),
        request_header_names: [...endpoint.requestHeaderNames].sort(),
        response_header_names: [...endpoint.responseHeaderNames].sort(),
        parameters: [...endpoint.parameters.entries()]
          .map(([key, entry]) => {
            const [location, name] = key.split("\u0000") as [
              MitmParameterLocation,
              string,
            ];
            return { name, location, types: [...entry.types] };
          })
          .sort(parameterOrder),
        response_shape: endpoint.shape,
        shape_variants: endpoint.shapeVariants,
      }));
    return {
      totals: {
        flows: this.#flows,
        endpoints: endpoints.length,
        endpoints_omitted: this.#endpointsOmitted,
        facts_omitted: this.#factsOmitted,
        requests_without_response: this.#withoutResponse,
        bodies_held: this.#bodiesHeld,
        body_bytes_held: this.#bodyBytesHeld,
      },
      endpoints,
    };
  }
}
