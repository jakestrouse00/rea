import { createHash } from "node:crypto";
import { z } from "zod";

import type { SanitizedBrowserUrl } from "../domain/browserObservation.js";
import type {
  BrowserScenarioEvent,
  BrowserScenarioEventOmissions,
} from "../domain/browserScenarioCaptureValues.js";
import type {
  BrowserNetworkBody,
  BrowserNetworkContentSelection,
  BrowserNetworkHeaders,
} from "../domain/browserNetworkEvidence.js";
import type { BrowserScenarioCaptureLimits } from "../domain/browserScenarioCaptureLimits.js";
import { DEFAULT_BROWSER_SCENARIO_CAPTURE_LIMITS } from "../domain/browserScenarioCaptureLimits.js";
import type { BrowserScenarioSecrets } from "./BrowserScenarioSecrets.js";
import { BrowserScenarioEventBudget } from "./BrowserScenarioEventBudget.js";

type EventName =
  | "console"
  | "page-errors"
  | "network"
  | "websockets"
  | "frames"
  | "workers"
  | "popups"
  | "downloads";

/** Child network header dictionaries; the bridge caps entries and values itself. */
const childHeadersSchema = z.record(z.string(), z.string());

const childNetworkDataSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("request"),
    request_id: z.string(),
    url: z.string(),
    method: z.string(),
    resource_type: z.string(),
    headers: childHeadersSchema.optional(),
    body: z.string().optional(),
    body_truncated: z.boolean().optional(),
  }),
  z.strictObject({
    kind: z.literal("response"),
    request_id: z.string(),
    url: z.string().nullable().optional(),
    status: z.number().int().nullable().optional(),
    status_text: z.string().optional(),
    mime_type: z.string().optional(),
    protocol: z.string().optional(),
    headers: childHeadersSchema.optional(),
    body: z.string().optional(),
    body_encoding: z.enum(["text", "base64"]).optional(),
    body_truncated: z.boolean().optional(),
  }),
  z.strictObject({
    kind: z.literal("request_failed"),
    request_id: z.string(),
    error_text: z.string(),
    url: z.string().optional(),
  }),
]);

const childWebSocketsDataSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("websocket_created"),
    request_id: z.string(),
    url: z.string(),
  }),
  z.strictObject({
    kind: z.literal("websocket_frame"),
    request_id: z.string(),
    direction: z.enum(["received", "sent"]),
    payload: z.string(),
    payload_encoding: z.literal("text").optional(),
    payload_truncated: z.boolean().optional(),
  }),
  z.strictObject({
    kind: z.literal("websocket_closed"),
    request_id: z.string(),
  }),
]);

const childConsoleDataSchema = z.strictObject({
  kind: z.literal("console"),
  level: z.string(),
  text: z.string(),
  text_truncated: z.boolean().optional(),
  url: z.string().optional(),
});

const childPageErrorDataSchema = z.strictObject({
  kind: z.literal("page_error"),
  message: z.string(),
  message_truncated: z.boolean().optional(),
  url: z.string().optional(),
  stack: z.string().optional(),
  stack_truncated: z.boolean().optional(),
});

/** The bridge emits frame navigations only; attach/detach events have no path. */
const childFramesDataSchema = z.strictObject({
  kind: z.literal("frame_navigated"),
  frame_id: z.string(),
  url: z.string(),
  is_main: z.boolean().optional(),
});

const childOversizedDataSchema = z.strictObject({
  kind: z.literal("event_oversized"),
});

const childQueueOverflowDataSchema = z.strictObject({
  kind: z.literal("event_queue_overflow"),
  count: z.number().int().min(1),
});

interface BridgeScenarioEvent {
  readonly family: string;
  readonly data: Record<string, unknown>;
}

interface CollectorOptions {
  readonly secrets: BrowserScenarioSecrets;
  readonly enabled: ReadonlySet<EventName>;
  readonly network?: BrowserNetworkContentSelection;
  readonly limits?: BrowserScenarioCaptureLimits;
}

interface NetworkHop {
  readonly transactionId: string;
  readonly redirectedFrom: string | null;
  method: string;
  url: string;
  resourceType: string;
  status: number | undefined;
  terminal: "finished" | "failed" | undefined;
}

const emptyNetworkSelection = {
  request_body: false,
  response_body: false,
  header_values: false,
} as const;

const BRIDGE_BODY_CAP_BYTES = 256 * 1024;

/** Maps streamed pydoll-bridge events into budgeted, redacted REA scenario events. */
export class PydollScenarioEvents {
  private readonly budget: BrowserScenarioEventBudget;
  private readonly enabled: ReadonlySet<EventName>;
  private readonly secrets: BrowserScenarioSecrets;
  private readonly limits: BrowserScenarioCaptureLimits;
  private readonly networkSelection: BrowserNetworkContentSelection;
  private readonly hopsByRequestId = new Map<
    string,
    { hops: NetworkHop[]; websocketUrl: string | undefined }
  >();
  private transactionCount = 0;
  private readonly omittedTransactions: string[] = [];
  private readonly familyGaps = new Set<string>();
  #sealed = false;

  constructor(options: CollectorOptions) {
    this.budget = new BrowserScenarioEventBudget({
      secrets: options.secrets,
      ...(options.limits === undefined ? {} : { limits: options.limits }),
    });
    this.secrets = options.secrets;
    this.limits = options.limits ?? DEFAULT_BROWSER_SCENARIO_CAPTURE_LIMITS;
    const network = options.network ?? emptyNetworkSelection;
    this.enabled =
      network.request_body || network.response_body || network.header_values
        ? new Set([...options.enabled, "network"])
        : new Set(options.enabled);
    this.networkSelection = network;
  }

  get sealed(): boolean {
    return this.#sealed;
  }

  setStep(index: number): void {
    this.budget.setStep(index);
  }

  nextSequence(): number {
    return this.budget.nextSequence();
  }

  lastSequence(): number {
    return this.budget.lastSequence();
  }

  /** Record one honest provider note as an event-coverage gap. */
  note(gap: string): void {
    if (this.#sealed) return;
    this.familyGaps.add(gap);
  }

  /** Ingest one bridge event ({family, data}); unknown kinds surface as gaps. */
  async ingest(childEvent: unknown): Promise<void> {
    if (this.#sealed) return;
    const parsed = parseBridgeScenarioEvent(childEvent);
    if (parsed === undefined)
      throw new Error("Bridge event is missing its family discriminant");
    const { family, data } = parsed;
    if (
      data.kind === "event_oversized" &&
      childOversizedDataSchema.safeParse(data).success
    ) {
      return this.note(
        `The bridge dropped an oversized ${family} event; that event is not captured.`,
      );
    }
    if (data.kind === "event_queue_overflow") {
      const overflow = childQueueOverflowDataSchema.safeParse(data);
      if (!overflow.success)
        throw new Error(
          "The bridge event-queue overflow marker does not match its contract",
        );
      return this.note(
        `The bridge dropped ${overflow.data.count} queued events when its bounded event queue overflowed; those events are not captured.`,
      );
    }
    switch (family) {
      case "console": {
        const parsedData = childConsoleDataSchema.safeParse(data);
        if (!parsedData.success)
          throw new Error(
            "The bridge console event does not match its contract",
          );
        return this.console(parsedData.data);
      }
      case "page-errors": {
        const parsedData = childPageErrorDataSchema.safeParse(data);
        if (!parsedData.success)
          throw new Error(
            "The bridge page-error event does not match its contract",
          );
        return this.pageError(parsedData.data);
      }
      case "frames": {
        const parsedData = childFramesDataSchema.safeParse(data);
        if (!parsedData.success)
          throw new Error("The bridge frame event does not match its contract");
        return this.frame(parsedData.data);
      }
      case "websockets": {
        const parsedData = childWebSocketsDataSchema.safeParse(data);
        if (!parsedData.success)
          throw new Error(
            "The bridge websocket event does not match its contract",
          );
        return this.webSocket(parsedData.data);
      }
      case "network": {
        const parsedData = childNetworkDataSchema.safeParse(data);
        if (!parsedData.success)
          throw new Error(
            "The bridge network event does not match its contract",
          );
        return await this.network(parsedData.data);
      }
      default:
        return this.note(
          `The bridge streamed unsupported "${family}" events; that family is not captured.`,
        );
    }
  }

  /** Stop ingesting and finalize unobserved transaction completion at the cutoff. */
  finish(cancelled: boolean): void {
    for (const [, ledger] of this.hopsByRequestId)
      for (const hop of ledger.hops) {
        if (hop.terminal !== undefined) continue;
        if (
          this.budget.admitProducerText(
            "request-unfinished",
            [hop.url, hop.method],
            true,
          ).status !== "retained"
        )
          continue;
        this.budget.push({
          kind: "request-unfinished",
          transaction_id: hop.transactionId,
          redirected_from_transaction_id: hop.redirectedFrom,
          method: this.secrets.redact(hop.method),
          url: this.safeUrl(hop.url),
          resource_type: this.secrets.redact(hop.resourceType),
          header_names: [],
          status: null,
          failure: null,
          reason: cancelled ? "cancelled" : "capture-ended",
        });
      }
    this.#sealed = true;
  }

  limitations(): readonly string[] {
    const gaps = [...this.familyGaps];
    if (this.enabled.has("network"))
      gaps.push(
        "The pydoll bridge does not observe request completion without body capture; a response receipt is not a completion observation, so transactions are closed by capture cutoff instead.",
      );
    if (this.enabled.has("frames"))
      gaps.push(
        "Frame attach and detach events are unavailable in the pydoll bridge; only frame navigations are captured.",
      );
    if (this.enabled.has("network") && this.omittedTransactions.length > 0)
      gaps.push(
        "Network transactions beyond the selected transaction budget were omitted; the omitted transaction range is listed in events.omissions.",
      );
    if (this.budget.result().dropped > 0)
      gaps.push(
        "Browser event collection reached a selected resource budget; per-kind omissions and affected network transaction IDs are listed in events.omissions, and event coverage is incomplete.",
      );
    return gaps;
  }

  result(): {
    readonly retained: number;
    readonly dropped: number;
    readonly items: readonly BrowserScenarioEvent[];
    readonly omissions: BrowserScenarioEventOmissions;
  } {
    const base = this.budget.result();
    const first = this.omittedTransactions[0];
    const last =
      this.omittedTransactions.length > 1
        ? this.omittedTransactions[this.omittedTransactions.length - 1]
        : undefined;
    return {
      retained: base.retained,
      dropped: base.dropped,
      items: base.items,
      omissions: {
        ...base.omissions,
        network_transaction_range:
          first === undefined
            ? null
            : {
                first_transaction_id: first,
                last_transaction_id: last ?? first,
                count: this.omittedTransactions.length,
                reason: "max-network-transactions" as const,
              },
      },
    };
  }

  private safeUrl(value: string): SanitizedBrowserUrl {
    return this.secrets.sanitizeUrl(value);
  }

  private console(data: z.infer<typeof childConsoleDataSchema>): void {
    if (!this.enabled.has("console")) return;
    if (data.text_truncated === true)
      this.note(
        "Console text was capped at the bridge transport bound; the captured text may be partial.",
      );
    if (
      this.budget.admitProducerText(
        "console",
        [data.text, data.url ?? ""],
        false,
      ).status !== "retained"
    )
      return;
    this.budget.push({
      kind: "console",
      level: this.secrets.redact(data.level),
      text: this.secrets.redact(data.text),
      url: (data.url ?? "") === "" ? null : this.safeUrl(data.url ?? ""),
    });
  }

  private pageError(data: z.infer<typeof childPageErrorDataSchema>): void {
    if (!this.enabled.has("page-errors")) return;
    if (data.message_truncated === true || data.stack_truncated === true)
      this.note(
        "A page-error message or stack was capped at the bridge transport bound; the captured text may be partial.",
      );
    if (
      this.budget.admitProducerText(
        "page-error",
        [data.message, data.stack ?? ""],
        false,
      ).status !== "retained"
    )
      return;
    this.budget.push({
      kind: "page-error",
      message: this.secrets.redact(data.message),
      stack: data.stack === undefined ? null : this.secrets.redact(data.stack),
    });
  }

  private frame(data: z.infer<typeof childFramesDataSchema>): void {
    if (!this.enabled.has("frames")) return;
    if (
      !this.budget.admitProducerText("frame-navigated", [data.url], false)
        .status
    )
      return;
    this.budget.push({
      kind: "frame-navigated",
      url: data.url === "" ? null : this.safeUrl(data.url),
      name: null,
    });
  }

  #webSocketLedger(
    data: { readonly request_id: string } & Record<string, unknown>,
  ) {
    let ledger = this.hopsByRequestId.get(data.request_id);
    if (ledger === undefined) {
      if (!("url" in data) || data.request_id === "") return undefined;
      ledger = { hops: [], websocketUrl: undefined };
      this.hopsByRequestId.set(data.request_id, ledger);
    }
    return ledger;
  }

  private webSocket(data: z.infer<typeof childWebSocketsDataSchema>): void {
    if (!this.enabled.has("websockets")) return;
    if (data.kind === "websocket_created") {
      const ledger = this.#webSocketLedger(data);
      if (ledger === undefined) return;
      ledger.websocketUrl = data.url;
      if (
        !this.budget.admitProducerText("websocket-opened", [data.url], false)
          .status
      )
        return;
      this.budget.push({
        kind: "websocket-opened",
        url: this.safeUrl(data.url),
      });
      return;
    }
    const ledger = this.hopsByRequestId.get(data.request_id);
    const url = ledger?.websocketUrl;
    if (ledger === undefined || url === undefined) {
      this.note(
        "A websocket event arrived without its create event; the frame or close is not captured.",
      );
      return;
    }
    if (data.kind === "websocket_closed") {
      if (
        !this.budget.admitProducerText("websocket-closed", [url], false).status
      )
        return;
      this.budget.push({ kind: "websocket-closed", url: this.safeUrl(url) });
      return;
    }
    const kind =
      data.direction === "sent"
        ? "websocket-frame-sent"
        : "websocket-frame-received";
    if (!this.budget.admitProducerText(kind, [data.payload], false).status)
      return;
    this.budget.push({
      kind,
      url: this.safeUrl(url),
      payload_type: "text",
      payload_bytes: Buffer.byteLength(data.payload),
      payload_text: this.secrets.redact(data.payload),
      truncated: data.payload_truncated === true,
    });
  }

  private async network(
    data: z.infer<typeof childNetworkDataSchema>,
  ): Promise<void> {
    if (!this.enabled.has("network")) return;
    switch (data.kind) {
      case "request":
        return this.networkRequest(data);
      case "response":
        return await this.networkResponse(data);
      case "request_failed":
        return this.networkFailed(data);
    }
  }

  #networkLedger(requestId: string) {
    let ledger = this.hopsByRequestId.get(requestId);
    if (ledger === undefined) {
      ledger = { hops: [], websocketUrl: undefined };
      this.hopsByRequestId.set(requestId, ledger);
    }
    return ledger;
  }

  #newTransaction(
    requestId: string,
    method: string,
    url: string,
    resourceType: string,
    redirectedFrom: string | null,
  ): NetworkHop | undefined {
    const transactionId = `cdp:${requestId}#${this.transactionCount}`;
    if (this.transactionCount >= this.limits.max_network_transactions) {
      if (!this.omittedTransactions.includes(transactionId))
        this.omittedTransactions.push(transactionId);
      return undefined;
    }
    this.transactionCount += 1;
    return {
      transactionId,
      redirectedFrom,
      method,
      url,
      resourceType,
      status: undefined,
      terminal: undefined,
    };
  }

  private networkRequest(
    data: Extract<z.infer<typeof childNetworkDataSchema>, { kind: "request" }>,
  ): void {
    if (data.url === "") {
      this.note(
        "A request event carried no URL; its transaction metadata is not captured.",
      );
      return;
    }
    const ledger = this.#networkLedger(data.request_id);
    const previous = ledger.hops[ledger.hops.length - 1];
    const hop = this.#newTransaction(
      data.request_id,
      data.method,
      data.url,
      data.resource_type,
      previous?.transactionId ?? null,
    );
    if (hop === undefined) {
      this.note(
        `Network transaction metadata for request ${this.secrets.redact(data.url) === data.url ? data.url : "a redirected request"} exceeded the transaction budget and its events were omitted.`,
      );
      return;
    }
    ledger.hops.push(hop);
    const headerNames =
      data.headers === undefined ? [] : Object.keys(data.headers);
    if (
      this.budget.admitProducerText(
        "request",
        [data.url, data.method, data.resource_type],
        true,
      ).status !== "retained"
    )
      return;
    const admission = this.budget.push({
      kind: "request",
      transaction_id: hop.transactionId,
      redirected_from_transaction_id: previous?.transactionId ?? null,
      redirected_from_transaction_state: undefined,
      method: this.secrets.redact(data.method),
      url: this.safeUrl(data.url),
      resource_type: this.secrets.redact(data.resource_type),
      header_names: headerNames,
      status: null,
      failure: null,
    });
    if (admission.status === "omitted") return;
    const content = this.contentFromEvent("request", {
      headers: data.headers,
      body: data.body,
      bodyTruncated: data.body_truncated === true,
      bodyEncoding: "text",
      mediaType: undefined,
    });
    if (content !== undefined)
      this.pushContent(
        hop.transactionId,
        admission.sequence,
        "request",
        content,
      );
  }

  private async networkResponse(
    data: Extract<z.infer<typeof childNetworkDataSchema>, { kind: "response" }>,
  ): Promise<void> {
    const hop = this.hopsByRequestId
      .get(data.request_id)
      ?.hops.find((candidate) => candidate.status === undefined);
    if (hop === undefined) {
      this.note(
        "A response event arrived without a tracked request; the response is not captured.",
      );
      return;
    }
    if (data.url) hop.url = data.url;
    if (data.status === null || data.status === undefined) {
      hop.terminal = "finished";
      this.note(
        "A response receipt lacked response metadata; the response event is not captured.",
      );
      return;
    }
    const responseEndedCapture = this.networkSelection.response_body === true;
    if (responseEndedCapture) hop.terminal = "finished";
    hop.status = data.status;
    const headerNames =
      data.headers === undefined ? [] : Object.keys(data.headers);
    if (
      this.budget.admitProducerText("response", [hop.url, hop.method], true)
        .status !== "retained"
    )
      return;
    const admission = this.budget.push({
      kind: "response",
      transaction_id: hop.transactionId,
      redirected_from_transaction_id: hop.redirectedFrom,
      method: this.secrets.redact(hop.method),
      url: this.safeUrl(hop.url),
      resource_type: this.secrets.redact(hop.resourceType),
      header_names: headerNames,
      status: data.status,
      failure: null,
    });
    if (admission.status === "omitted") return;
    const content = this.contentFromEvent("response", {
      headers: data.headers,
      body: data.body,
      bodyTruncated: data.body_truncated === true,
      bodyEncoding: data.body_encoding ?? "text",
      mediaType: data.mime_type,
    });
    if (content !== undefined)
      this.pushContent(
        hop.transactionId,
        admission.sequence,
        "response",
        content,
      );
  }

  private networkFailed(
    data: Extract<
      z.infer<typeof childNetworkDataSchema>,
      { kind: "request_failed" }
    >,
  ): void {
    const ledger = this.hopsByRequestId.get(data.request_id);
    const hops = ledger?.hops ?? [];
    const hop =
      [...hops]
        .reverse()
        .find((candidate) => candidate.terminal === undefined) ??
      hops[hops.length - 1];
    if (hop === undefined) {
      this.note(
        "A request failure arrived without a tracked request; the failure is not captured.",
      );
      return;
    }
    hop.terminal = "failed";
    const failure = data.error_text === "" ? "network error" : data.error_text;
    const url = data.url !== undefined && data.url !== "" ? data.url : hop.url;
    if (
      this.budget.admitProducerText("request-failed", [failure, url], true)
        .status !== "retained"
    )
      return;
    if (
      this.budget.push({
        kind: "request-failed",
        transaction_id: hop.transactionId,
        redirected_from_transaction_id: hop.redirectedFrom,
        method: this.secrets.redact(hop.method),
        url: this.safeUrl(url),
        resource_type: this.secrets.redact(hop.resourceType),
        header_names: [],
        status: null,
        failure: this.secrets.redact(failure),
      }).status === "omitted"
    )
      this.budget.omitNetwork(
        hop.transactionId,
        "request-failed",
        "max-events",
      );
  }

  private contentFromEvent(
    phase: "request" | "response",
    input: {
      readonly headers: Record<string, string> | undefined;
      readonly body: string | undefined;
      readonly bodyTruncated: boolean;
      readonly bodyEncoding: "text" | "base64";
      readonly mediaType: string | undefined;
    },
  ):
    | {
        readonly headers: BrowserNetworkHeaders;
        readonly body: BrowserNetworkBody;
      }
    | undefined {
    const bodySelected =
      phase === "request"
        ? this.networkSelection.request_body
        : this.networkSelection.response_body;
    const wantHeaders =
      this.networkSelection.header_values === true &&
      input.headers !== undefined;
    const wantBody =
      (bodySelected === true && input.body !== undefined) || wantHeaders;
    if (!wantHeaders && !wantBody) return undefined;
    let headers: BrowserNetworkHeaders;
    if (!this.networkSelection.header_values || input.headers === undefined)
      headers = { state: "not_requested" as const };
    else {
      const entries = Object.entries(input.headers);
      const cost =
        256 +
        entries.reduce(
          (sum, [name, value]) =>
            sum +
            name.length * 8 +
            2 +
            this.secrets.redactionAllocationCost(value.length),
          0,
        );
      headers =
        cost > this.limits.max_network_header_allocation_bytes
          ? {
              state: "unavailable" as const,
              message: `Header values exceed the ${String(this.limits.max_network_header_allocation_bytes)}-byte allocation budget.`,
            }
          : {
              state: "captured" as const,
              items: entries.map(([name, value]) => ({
                name: this.secrets.redact(name),
                value: this.secrets.redact(value),
                redacted: this.secrets.redact(value) !== value,
              })),
            };
    }
    let body: BrowserNetworkBody;
    if (input.body === undefined)
      body = bodySelected
        ? { state: "not_exposed" as const }
        : { state: "not_requested" as const };
    else if (!bodySelected) body = { state: "not_requested" as const };
    else if (input.bodyTruncated)
      body = {
        state: "unavailable" as const,
        reason: "body-size-limit" as const,
        message: "Body bytes exceed the bridge transport bound.",
        limit_bytes: BRIDGE_BODY_CAP_BYTES,
        observed_bytes: BRIDGE_BODY_CAP_BYTES,
      };
    else
      body = this.capturedBody(input.body, input.bodyEncoding, input.mediaType);
    return { headers, body };
  }

  private capturedBody(
    body: string,
    encoding: "text" | "base64",
    mediaType: string | undefined,
  ): BrowserNetworkBody {
    const bytes =
      encoding === "base64" ? Buffer.from(body, "base64") : Buffer.from(body);
    if (bytes.byteLength > this.limits.max_network_body_bytes)
      return {
        state: "unavailable" as const,
        reason: "body-size-limit" as const,
        message: "Body bytes exceed the selected body budget.",
        limit_bytes: this.limits.max_network_body_bytes,
        observed_bytes: bytes.byteLength,
      };
    const redacted = this.secrets.redactBytes(bytes);
    return {
      state: "captured" as const,
      representation:
        encoding === "base64"
          ? "browser-decoded-response-bytes"
          : "browser-exposed-request-bytes",
      encoding: "base64" as const,
      content: redacted.toString("base64"),
      bytes: redacted.byteLength,
      sha256: createHash("sha256").update(redacted).digest("hex"),
      media_type: mediaType ?? null,
      redacted: !redacted.equals(bytes),
    };
  }

  private pushContent(
    transactionId: string,
    sourceEventSequence: number,
    phase: "request" | "response",
    content: {
      readonly headers: BrowserNetworkHeaders;
      readonly body: BrowserNetworkBody;
    },
  ): void {
    if (
      this.budget.admitContentBody({
        transactionId,
        sourceEventSequence,
        phase,
        headers: content.headers,
        observedBytes:
          content.body.state === "captured" ? content.body.bytes : 0,
        allocationBytes:
          content.body.state === "captured" ? content.body.content.length : 0,
        mediaType: undefined,
        representation:
          content.body.state === "captured"
            ? content.body.representation
            : "browser-exposed-request-bytes",
      }).status === "omitted"
    ) {
      this.budget.omitNetwork(transactionId, "network-content", "max-events");
      return;
    }
    this.budget.push({
      kind: "network-content",
      transaction_id: transactionId,
      source_event_sequence: sourceEventSequence,
      phase,
      headers: content.headers,
      body: content.body,
    });
  }
}

const parseBridgeScenarioEvent = (
  childEvent: unknown,
):
  | { readonly family: string; readonly data: Record<string, unknown> }
  | undefined => {
  if (typeof childEvent !== "object" || childEvent === null) return undefined;
  const family = (childEvent as { family?: unknown }).family;
  if (typeof family !== "string") return undefined;
  const data = (childEvent as { data?: unknown }).data;
  if (typeof data !== "object" || data === null || Array.isArray(data))
    return undefined;
  if ((data as { kind?: unknown }).kind === undefined)
    return { family, data: {} };
  return { family, data: data as Record<string, unknown> };
};
