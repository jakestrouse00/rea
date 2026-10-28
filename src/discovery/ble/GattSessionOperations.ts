import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisError as AnalysisErrorClass } from "../../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok, type Result } from "../../domain/result.js";
import { DISCOVERY_PROVIDER_ID } from "../DiscoveryRelease.js";
import {
  GattSessionManager,
  type GattNotificationRow,
  isGattSessionUnknown,
} from "./GattSessionManager.js";
import type { ParsedGattService } from "./GattAnalysis.js";

export const GATT_ENUMERATE_OPERATION = "enumerate_gatt_services";
export const GATT_SUBSCRIBE_OPERATION = "subscribe_characteristic";

const outcomeIntoError = (
  operation: string,
  failure: {
    readonly code: string;
    readonly reason: string;
  },
): AnalysisError =>
  failure.code === "session_unknown" || failure.code === "command_refused"
    ? new AnalysisInputError(operation, { userMessage: failure.reason })
    : new ProviderAdapterError(DISCOVERY_PROVIDER_ID, operation, {
        userMessage: failure.reason,
      });

const requireSessionOutcome = (
  cause: unknown,
  operation: string,
): AnalysisError => {
  if (isGattSessionUnknown(cause))
    return new AnalysisInputError(operation, {
      userMessage: (cause as Error).message,
    });
  return new ProviderAdapterError(DISCOVERY_PROVIDER_ID, operation, {
    userMessage:
      cause instanceof Error
        ? cause.message
        : `The GATT session manager refused ${operation}`,
  });
};

/** One bounded service enumeration with the omissions it counted. */
export interface GattServiceEnumeration {
  readonly session_id: string;
  readonly peripheral_id: string;
  readonly services: readonly ParsedGattService[];
  readonly service_count: number;
  readonly characteristics_omitted: number;
  readonly services_truncated: boolean;
  readonly elapsed_ms: number;
  readonly unparsed_lines: readonly string[];
}

/**
 * Re-enumerate the session's own service tree. A peripheral can publish
 * services after the connection handshake (a bonded peer, for example), so
 * this asks the live helper rather than replaying the handshake's answer.
 */
export const executeGattEnumerate = async (
  sessions: GattSessionManager,
  input: {
    readonly session_id: string;
    readonly max_services: number;
    readonly max_characteristics_per_service: number;
  },
  signal: AbortSignal | undefined,
  operationTimeoutMs: number,
): Promise<Result<GattServiceEnumeration, AnalysisError>> => {
  const started = Date.now();
  try {
    const response = await sessions.command(
      input.session_id,
      GATT_ENUMERATE_OPERATION,
      { op: "enumerate" },
      {
        deadlineMs: operationTimeoutMs,
        signal,
        includePayloadHex: false,
        collectNotifications: false,
      },
    );
    if (!response.ok) {
      if (response.error instanceof AnalysisErrorClass)
        return err(response.error);
      return err(outcomeIntoError(GATT_ENUMERATE_OPERATION, response.error));
    }
    const facts = sessions.factsOf(input.session_id);
    if (facts === null || response.value.services === null)
      return err(
        new ProviderAdapterError(
          DISCOVERY_PROVIDER_ID,
          GATT_ENUMERATE_OPERATION,
          {
            userMessage:
              "The helper's enumerate reply carried no service tree; the session was closed",
          },
        ),
      );
    const enumerated = response.value.services;
    let characteristicsOmitted = 0;
    const services = enumerated.slice(0, input.max_services).map((service) => {
      const characteristics = service.characteristics.slice(
        0,
        input.max_characteristics_per_service,
      );
      characteristicsOmitted +=
        service.characteristics.length - characteristics.length;
      return { uuid: service.uuid, characteristics: [...characteristics] };
    });
    return ok({
      session_id: input.session_id,
      peripheral_id: facts.peripheral_id,
      services,
      service_count: enumerated.length,
      characteristics_omitted: characteristicsOmitted,
      services_truncated:
        enumerated.length > services.length || characteristicsOmitted > 0,
      elapsed_ms: Date.now() - started,
      unparsed_lines: response.value.unparsed_lines,
    });
  } catch (cause: unknown) {
    return err(requireSessionOutcome(cause, GATT_ENUMERATE_OPERATION));
  }
};

/** One bounded subscription window with its buffer accounting. */
export interface GattSubscription {
  readonly session_id: string;
  readonly peripheral_id: string;
  readonly service_uuid: string;
  readonly characteristic_uuid: string;
  readonly observe_seconds: number;
  readonly max_notifications: number;
  readonly notifications: readonly GattNotificationRow[];
  readonly notification_count: number;
  readonly buffer_full: boolean;
  readonly window_exhausted: boolean;
  readonly stop_reason: "deadline" | "buffer_full";
  readonly elapsed_ms: number;
  readonly unparsed_lines: readonly string[];
}

/**
 * Subscribe to one notifiable characteristic and collect its notifications
 * into a bounded buffer. The window ends at the caller's deadline or when the
 * retained buffer is full; a full buffer is a complete observation of what it
 * held, never a claim about what came later.
 */
export const executeGattSubscribe = async (
  sessions: GattSessionManager,
  input: {
    readonly session_id: string;
    readonly service_uuid: string;
    readonly characteristic_uuid: string;
    readonly observe_seconds: number;
    readonly max_notifications: number;
    readonly include_payload_hex: boolean;
  },
  signal: AbortSignal | undefined,
): Promise<Result<GattSubscription, AnalysisError>> => {
  const started = Date.now();
  try {
    const response = await sessions.command(
      input.session_id,
      GATT_SUBSCRIBE_OPERATION,
      {
        op: "subscribe",
        service: input.service_uuid,
        characteristic: input.characteristic_uuid,
        seconds: input.observe_seconds,
        max_notifications: input.max_notifications,
      },
      {
        deadlineMs: input.observe_seconds * 1000 + 10_000,
        signal,
        includePayloadHex: input.include_payload_hex,
        collectNotifications: true,
        maxNotifications: input.max_notifications,
      },
    );
    if (!response.ok) {
      if (response.error instanceof AnalysisErrorClass)
        return err(response.error);
      return err(outcomeIntoError(GATT_SUBSCRIBE_OPERATION, response.error));
    }
    const facts = sessions.factsOf(input.session_id);
    if (facts === null)
      return err(
        new ProviderAdapterError(
          DISCOVERY_PROVIDER_ID,
          GATT_SUBSCRIBE_OPERATION,
          {
            userMessage:
              "The session ended with the subscription window in flight",
          },
        ),
      );
    const bufferFull =
      response.value.stop_reason === "buffer_full" ||
      response.value.notifications_omitted > 0;
    return ok({
      session_id: input.session_id,
      peripheral_id: facts.peripheral_id,
      service_uuid: input.service_uuid,
      characteristic_uuid: input.characteristic_uuid,
      observe_seconds: input.observe_seconds,
      max_notifications: input.max_notifications,
      notifications: response.value.notifications,
      notification_count:
        response.value.notifications.length +
        response.value.notifications_omitted,
      buffer_full: bufferFull,
      window_exhausted: !bufferFull,
      stop_reason: bufferFull ? "buffer_full" : "deadline",
      elapsed_ms: Date.now() - started,
      unparsed_lines: response.value.unparsed_lines,
    });
  } catch (cause: unknown) {
    return err(requireSessionOutcome(cause, GATT_SUBSCRIBE_OPERATION));
  }
};
