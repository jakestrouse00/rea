import {
  browserScenarioEventSchema,
  type BrowserScenarioEvent,
} from "../domain/browserScenarioCaptureValues.js";
import type {
  BrowserScenarioEventAdmission,
  BrowserScenarioEventBudgetReason,
  BrowserScenarioEventOmissions,
} from "../domain/browserScenarioCaptureValues.js";
import type { BrowserNetworkHeaders } from "../domain/browserNetworkEvidence.js";
import type { BrowserScenarioCaptureLimits } from "../domain/browserScenarioCaptureLimits.js";
import { DEFAULT_BROWSER_SCENARIO_CAPTURE_LIMITS } from "../domain/browserScenarioCaptureLimits.js";
import type { BrowserScenarioSecrets } from "./BrowserScenarioSecrets.js";

export type BrowserScenarioUnindexedEvent =
  BrowserScenarioEvent extends infer Event
    ? Event extends BrowserScenarioEvent
      ? Omit<Event, "sequence" | "step_index">
      : never
    : never;
// Conservative allocation accounting includes UTF-16 storage and worst-case
// JSON escaping. Check before schema cloning; never serialize to measure.
export const allocationCost = (value: unknown, remaining: number): number => {
  if (typeof value === "string") return value.length * 8 + 2;
  if (value === null || typeof value !== "object") return 32;
  let cost = 2;
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    const item = (value as Record<string, unknown>)[key];
    cost += key.length * 8 + 4 + allocationCost(item, remaining - cost);
    if (cost > remaining) break;
  }
  return cost;
};

/**
 * Arrival-ordered event admission shared by every scenario session provider:
 * one place owns sequence assignment, budget omissions, and result shape.
 */
export class BrowserScenarioEventBudget {
  private readonly items: BrowserScenarioEvent[] = [];
  private retainedCost = 0;
  private dropped = 0;
  private readonly omittedKinds = new Map<
    BrowserScenarioEvent["kind"],
    { count: number; reasons: Set<BrowserScenarioEventBudgetReason> }
  >();
  private readonly omittedNetwork = new Map<
    string,
    {
      readonly kinds: Set<BrowserScenarioEvent["kind"]>;
      readonly reasons: Set<BrowserScenarioEventBudgetReason>;
    }
  >();
  private stepIndex = 0;
  private sequence = 0;
  private readonly limits: BrowserScenarioCaptureLimits;
  private readonly secrets: BrowserScenarioSecrets;
  #sealed = false;

  constructor(options: {
    readonly secrets: BrowserScenarioSecrets;
    readonly limits?: BrowserScenarioCaptureLimits;
  }) {
    this.secrets = options.secrets;
    this.limits = options.limits ?? DEFAULT_BROWSER_SCENARIO_CAPTURE_LIMITS;
  }

  setStep(index: number): void {
    this.stepIndex = index;
  }

  nextSequence(): number {
    return this.sequence + 1;
  }

  lastSequence(): number {
    return this.sequence;
  }

  get sealed(): boolean {
    return this.#sealed;
  }

  /** Reserve one sequence number for an omitted arrival without pushing an event. */
  bump(): void {
    this.sequence += 1;
  }

  /** Freeze the result before browser teardown; later arrivals are budget omissions. */
  seal(): void {
    this.#sealed = true;
  }

  push(event: BrowserScenarioUnindexedEvent): BrowserScenarioEventAdmission {
    this.sequence += 1;
    const cost =
      allocationCost(event, this.limits.max_event_allocation_bytes) + 128;
    const reason = this.admissionReason(cost);
    if (this.#sealed || reason !== undefined) {
      const finalReason = reason ?? "max-events";
      this.omitEvent(event.kind, finalReason);
      return {
        status: "omitted",
        sequence: this.sequence,
        reason: finalReason,
      };
    }
    this.retainedCost += cost;
    const parsed = browserScenarioEventSchema.parse({
      ...event,
      sequence: this.sequence,
      step_index: this.stepIndex,
    });
    this.items.push(parsed);
    return { status: "retained", sequence: this.sequence };
  }

  /** Admit conservative output cost before running redaction or cloning. */
  admitProducerText(
    kind: BrowserScenarioEvent["kind"],
    values: Iterable<string>,
    networkMetadata: boolean,
  ): BrowserScenarioEventAdmission {
    let cost = 4096;
    for (const value of values) {
      cost += this.secrets.redactionAllocationCost(value.length);
    }
    const reason =
      networkMetadata &&
      cost > this.limits.max_network_metadata_allocation_bytes
        ? "max-network-metadata-allocation-bytes"
        : this.admissionReason(cost);
    if (reason !== undefined) {
      this.sequence += 1;
      this.omitEvent(kind, reason);
      return { status: "omitted", sequence: this.sequence, reason };
    }
    return { status: "retained", sequence: this.sequence + 1 };
  }

  admitContentBody(input: {
    readonly transactionId: string;
    readonly sourceEventSequence: number;
    readonly phase: "request" | "response";
    readonly headers: BrowserNetworkHeaders;
    readonly observedBytes: number;
    readonly allocationBytes: number;
    readonly mediaType: string | undefined;
    readonly representation: string;
  }): BrowserScenarioEventAdmission {
    const kind = "network-content";
    const eventCost =
      allocationCost(
        {
          kind,
          sequence: this.sequence + 1,
          step_index: this.stepIndex,
          transaction_id: input.transactionId,
          source_event_sequence: input.sourceEventSequence,
          phase: input.phase,
          headers: input.headers,
          body: {
            state: "captured",
            representation: input.representation,
            encoding: "base64",
            content: null,
            bytes: input.observedBytes,
            sha256: "0".repeat(64),
            media_type: null,
            redacted: false,
          },
        },
        this.limits.max_event_allocation_bytes,
      ) -
      64 +
      input.allocationBytes +
      (input.mediaType === undefined
        ? 0
        : Math.max(
            input.mediaType.length * 8 + 2,
            this.secrets.redactionAllocationCost(input.mediaType.length),
          )) +
      128;
    const reason = this.admissionReason(eventCost);
    if (reason !== undefined) {
      this.sequence += 1;
      this.omitEvent(kind, reason);
      return { status: "omitted", sequence: this.sequence, reason };
    }
    return { status: "retained", sequence: this.sequence + 1 };
  }

  omitEvent(
    kind: BrowserScenarioEvent["kind"],
    reason: BrowserScenarioEventBudgetReason,
  ): void {
    this.dropped += 1;
    let omission = this.omittedKinds.get(kind);
    if (omission === undefined) {
      omission = { count: 0, reasons: new Set() };
      this.omittedKinds.set(kind, omission);
    }
    omission.count += 1;
    omission.reasons.add(reason);
  }

  omitNetwork(
    transactionId: string,
    kind: BrowserScenarioEvent["kind"],
    reason: BrowserScenarioEventBudgetReason,
  ): void {
    let omission = this.omittedNetwork.get(transactionId);
    if (omission === undefined) {
      omission = { kinds: new Set(), reasons: new Set() };
      this.omittedNetwork.set(transactionId, omission);
    }
    omission.kinds.add(kind);
    omission.reasons.add(reason);
  }

  result(): {
    readonly retained: number;
    readonly dropped: number;
    readonly items: readonly BrowserScenarioEvent[];
    readonly omissions: BrowserScenarioEventOmissions;
  } {
    const omittedKinds = new Map(
      [...this.omittedKinds].map(
        ([kind, omission]) =>
          [
            kind,
            { count: omission.count, reasons: new Set(omission.reasons) },
          ] as const,
      ),
    );
    return {
      retained: this.items.length,
      dropped: this.dropped,
      items: this.items,
      omissions: {
        by_kind: [...omittedKinds]
          .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
          .map(([kind, omission]) => ({
            kind,
            count: omission.count,
            reasons: [...omission.reasons].sort(),
          })),
        network_transactions: [...this.omittedNetwork]
          .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
          .map(([transaction_id, omission]) => ({
            transaction_id,
            omitted_kinds: [...omission.kinds].sort(),
            reasons: [...omission.reasons].sort(),
          })),
        network_transaction_range: null,
      },
    };
  }

  private admissionReason(
    cost: number,
  ): BrowserScenarioEventBudgetReason | undefined {
    if (this.#sealed || this.items.length >= this.limits.max_events)
      return "max-events";
    if (cost > this.limits.max_event_allocation_bytes)
      return "max-event-allocation-bytes";
    if (cost > this.limits.max_total_event_allocation_bytes - this.retainedCost)
      return "max-total-event-allocation-bytes";
    return undefined;
  }
}
