import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisError as AnalysisErrorClass } from "../../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok, type Result } from "../../domain/result.js";
import { DISCOVERY_PROVIDER_ID } from "../DiscoveryRelease.js";
import {
  GattSessionManager,
  type GattNotificationRow,
  type GattSessionFailure,
  type GattSessionOpened,
  isGattSessionUnknown,
} from "./GattSessionManager.js";

export const GATT_CONNECT_OPERATION = "connect_ble_gatt";
export const GATT_READ_OPERATION = "read_gatt_characteristic";
export const GATT_WRITE_OPERATION = "write_gatt_characteristic";
export const GATT_OBSERVE_OPERATION = "observe_gatt_notifications";
export const GATT_CLOSE_OPERATION = "close_ble_gatt";

/** Shared limitations carried by every GATT Evidence record. */
export const gattLimitations = (): string[] => [
  "The GATT session drives a caller-supplied CoreBluetooth helper; REA never pairs, installs, or rebuilds the helper, and macOS may prompt for Bluetooth permission on first use",
  "macOS reports BLE peripherals by CoreBluetooth UUID, never by Bluetooth MAC address, and peripheral identifiers can rotate between scans",
  "GATT payloads are reported value-free by default: a length and SHA-256 digest; payload hex appears only when the caller opted in on that command",
];

const outcomeIntoError = (
  operation: string,
  failure: GattSessionFailure,
): AnalysisError => {
  if (failure.code === "authorization_denied")
    return new ProviderAdapterError(DISCOVERY_PROVIDER_ID, operation, {
      userMessage: `${failure.reason} Grant Bluetooth access to the terminal or app that launches REA in System Settings, Privacy & Security, Bluetooth; then retry once.`,
      remediationAction: "grant_bluetooth_authorization",
    });
  if (
    failure.code === "session_unknown" ||
    failure.code === "connect_timeout" ||
    failure.code === "connect_refused" ||
    failure.code === "protocol_violation" ||
    failure.code === "peer_disconnected" ||
    failure.code === "command_refused" ||
    failure.code === "helper_missing"
  )
    return new ProviderAdapterError(DISCOVERY_PROVIDER_ID, operation, {
      userMessage: failure.reason,
    });
  return new ProviderAdapterError(DISCOVERY_PROVIDER_ID, operation, {
    userMessage: `The GATT helper refused ${operation}`,
  });
};

/** Open one session; the returned payload is Evidence-ready as-is. */
export const executeGattConnect = async (
  sessions: GattSessionManager,
  helperPath: string,
  input: {
    readonly peripheral_id: string;
    readonly connect_timeout_ms: number;
  },
  signal: AbortSignal | undefined,
): Promise<
  Result<
    {
      session_id: string;
      peripheral_id: string;
      name: string | null;
      services: GattSessionOpened["services"];
      elapsed_ms: number;
    },
    AnalysisError
  >
> => {
  const started = Date.now();
  try {
    const opened = await sessions.open(helperPath, input, signal);
    if (!opened.ok) {
      if (opened.error instanceof AnalysisErrorClass) return err(opened.error);
      return err(outcomeIntoError(GATT_CONNECT_OPERATION, opened.error));
    }
    return ok({ ...opened.value, elapsed_ms: Date.now() - started });
  } catch (cause: unknown) {
    return err(requireSessionOutcome(cause, GATT_CONNECT_OPERATION));
  }
};

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

/**
 * Read one characteristic via the session's live helper. The value is
 * value-free by default: digest and length; hex only on the opt-in.
 */
export const executeGattRead = async (
  sessions: GattSessionManager,
  input: {
    readonly session_id: string;
    readonly service_uuid: string;
    readonly characteristic_uuid: string;
    readonly include_payload_hex: boolean;
  },
  signal: AbortSignal | undefined,
  operationTimeoutMs: number,
): Promise<
  Result<
    {
      session_id: string;
      peripheral_id: string;
      service_uuid: string;
      characteristic_uuid: string;
      len: number | null;
      sha256: string | null;
      payload_hex: string | null;
      elapsed_ms: number;
    },
    AnalysisError
  >
> => {
  const started = Date.now();
  try {
    const response = await sessions.command(
      input.session_id,
      GATT_READ_OPERATION,
      {
        op: "read",
        service: input.service_uuid,
        characteristic: input.characteristic_uuid,
      },
      {
        deadlineMs: operationTimeoutMs,
        signal,
        includePayloadHex: input.include_payload_hex,
        collectNotifications: false,
      },
    );
    if (!response.ok) {
      if (response.error instanceof AnalysisErrorClass)
        return err(response.error);
      return err(outcomeIntoError(GATT_READ_OPERATION, response.error));
    }
    const facts = sessions.factsOf(input.session_id);
    if (facts === null || response.value.payload === null)
      return err(
        new ProviderAdapterError(DISCOVERY_PROVIDER_ID, GATT_READ_OPERATION, {
          userMessage:
            "The helper's read response carried no value; the session was closed",
        }),
      );
    return ok({
      session_id: input.session_id,
      peripheral_id: facts.peripheral_id,
      service_uuid: input.service_uuid,
      characteristic_uuid: input.characteristic_uuid,
      len: response.value.payload.len,
      sha256: response.value.payload.sha256,
      payload_hex: response.value.payload.payload_hex,
      elapsed_ms: Date.now() - started,
    });
  } catch (cause: unknown) {
    return err(requireSessionOutcome(cause, GATT_READ_OPERATION));
  }
};

/**
 * Send the caller's bytes exactly once; the payload is not echoed into
 * Evidence — the write is accounted by byte count and target only.
 */
export const executeGattWrite = async (
  sessions: GattSessionManager,
  input: {
    readonly session_id: string;
    readonly service_uuid: string;
    readonly characteristic_uuid: string;
    readonly payload_hex: string;
    readonly without_response: boolean;
  },
  signal: AbortSignal | undefined,
  operationTimeoutMs: number,
): Promise<
  Result<
    {
      session_id: string;
      peripheral_id: string;
      service_uuid: string;
      characteristic_uuid: string;
      bytes_written: number;
      without_response: boolean;
      elapsed_ms: number;
    },
    AnalysisError
  >
> => {
  const started = Date.now();
  try {
    const response = await sessions.command(
      input.session_id,
      GATT_WRITE_OPERATION,
      {
        op: "write",
        service: input.service_uuid,
        characteristic: input.characteristic_uuid,
        payload_hex: input.payload_hex.toLowerCase(),
        without_response: input.without_response,
      },
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
      return err(outcomeIntoError(GATT_WRITE_OPERATION, response.error));
    }
    const facts = sessions.factsOf(input.session_id);
    if (facts === null)
      return err(
        new ProviderAdapterError(DISCOVERY_PROVIDER_ID, GATT_WRITE_OPERATION, {
          userMessage: "The session ended with the write in flight",
        }),
      );
    return ok({
      session_id: input.session_id,
      peripheral_id: facts.peripheral_id,
      service_uuid: input.service_uuid,
      characteristic_uuid: input.characteristic_uuid,
      bytes_written: Buffer.byteLength(input.payload_hex, "hex"),
      without_response: input.without_response,
      elapsed_ms: Date.now() - started,
    });
  } catch (cause: unknown) {
    return err(requireSessionOutcome(cause, GATT_WRITE_OPERATION));
  }
};

/**
 * Collect one bounded notification window via the session's live helper.
 * The window is terminal only on the helper's window_end, a peer error,
 * the deadline, or cancellation.
 */
export const executeGattObserve = async (
  sessions: GattSessionManager,
  input: {
    readonly session_id: string;
    readonly service_uuid: string;
    readonly characteristic_uuid: string;
    readonly observe_seconds: number;
    readonly include_payload_hex: boolean;
  },
  signal: AbortSignal | undefined,
): Promise<
  Result<
    {
      session_id: string;
      peripheral_id: string;
      service_uuid: string;
      characteristic_uuid: string;
      observe_seconds: number;
      subscribed: boolean;
      notifications: readonly GattNotificationRow[];
      window_exhausted: boolean;
      stop_reason: "deadline" | "cancelled" | "peer_disconnect" | "error";
      elapsed_ms: number;
      unparsed_lines: readonly string[];
    },
    AnalysisError
  >
> => {
  const started = Date.now();
  try {
    const response = await sessions.command(
      input.session_id,
      GATT_OBSERVE_OPERATION,
      {
        op: "observe",
        service: input.service_uuid,
        characteristic: input.characteristic_uuid,
        seconds: input.observe_seconds,
      },
      {
        deadlineMs: input.observe_seconds * 1000 + 10_000,
        signal,
        includePayloadHex: input.include_payload_hex,
        collectNotifications: true,
      },
    );
    if (!response.ok) {
      if (response.error instanceof AnalysisErrorClass)
        return err(response.error);
      return err(outcomeIntoError(GATT_OBSERVE_OPERATION, response.error));
    }
    const facts = sessions.factsOf(input.session_id);
    if (facts === null)
      return err(
        new ProviderAdapterError(
          DISCOVERY_PROVIDER_ID,
          GATT_OBSERVE_OPERATION,
          {
            userMessage:
              "The session ended with the observation window in flight",
          },
        ),
      );
    return ok({
      session_id: input.session_id,
      peripheral_id: facts.peripheral_id,
      service_uuid: input.service_uuid,
      characteristic_uuid: input.characteristic_uuid,
      observe_seconds: input.observe_seconds,
      subscribed: true,
      notifications: response.value.notifications,
      window_exhausted: true,
      stop_reason: "deadline" as const,
      elapsed_ms: Date.now() - started,
      unparsed_lines: response.value.unparsed_lines,
    });
  } catch (cause: unknown) {
    return err(requireSessionOutcome(cause, GATT_OBSERVE_OPERATION));
  }
};

/**
 * Disconnect the named session cleanly; cleanup uncertainty left by the
 * escalation path is reported in detail.
 */
export const executeGattClose = async (
  sessions: GattSessionManager,
  input: { readonly session_id: string },
  signal: AbortSignal | undefined,
): Promise<
  Result<
    {
      session_id: string;
      peripheral_id: string;
      name: string | null;
      clean: boolean;
      detail: string | null;
      elapsed_ms: number;
    },
    AnalysisError
  >
> => {
  const started = Date.now();
  const facts = sessions.factsOf(input.session_id);
  if (facts === null)
    return err(
      new AnalysisInputError(GATT_CLOSE_OPERATION, {
        userMessage: `No open GATT session ${input.session_id} for close_ble_gatt`,
      }),
    );
  try {
    const closed = await sessions.close(input.session_id, signal);
    if (!closed.ok) return err(closed.error);
    return ok({
      session_id: facts.session_id,
      peripheral_id: facts.peripheral_id,
      name: facts.name,
      clean: closed.value.clean,
      detail: closed.value.detail,
      elapsed_ms: Date.now() - started,
    });
  } catch (cause: unknown) {
    return err(requireSessionOutcome(cause, GATT_CLOSE_OPERATION));
  }
};
