import type {
  BrowserRequestRuleDecision,
  BrowserRequestRuleOmissionReason,
} from "../domain/browserMutationLimits.js";
import { BROWSER_MUTATION_LIMITS } from "../domain/browserMutationLimits.js";
import type { browserRequestRuleDecisionSchema } from "../domain/browserMutation.js";
import type { z } from "zod";
import { allocationCost } from "./BrowserScenarioEventBudget.js";

export type BrowserRequestRuleDecisionRecord = z.output<
  typeof browserRequestRuleDecisionSchema
>;

/**
 * Retained interception-decision ledger for one armed rule.
 *
 * Enforcement is never budgeted: every matching request is still blocked,
 * modified, or held. Only the observation is dropped once the ledger reaches
 * its bounds, so a rewritten-traffic flood reports an explicit partial
 * observation instead of growing without limit.
 */
export class BrowserRequestRuleBudget {
  readonly #items: BrowserRequestRuleDecisionRecord[] = [];
  readonly #omitted = new Map<
    BrowserRequestRuleDecision,
    { count: number; reasons: Set<BrowserRequestRuleOmissionReason> }
  >();
  #retainedCost = 0;
  #dropped = 0;
  #sequence = 0;

  /** Admit one decision in arrival order, or record why it was not retained. */
  push(decision: Omit<BrowserRequestRuleDecisionRecord, "sequence">): void {
    this.#sequence += 1;
    const sequence = this.#sequence;
    const cost =
      allocationCost(
        { ...decision, sequence },
        BROWSER_MUTATION_LIMITS.maxRuleDecisionAllocationBytes,
      ) + 128;
    const reason = this.#admissionReason(cost);
    if (reason !== undefined) {
      this.#omit(decision.decision, reason);
      return;
    }
    this.#retainedCost += cost;
    this.#items.push({ ...decision, sequence });
  }

  result(): {
    readonly retained: number;
    readonly dropped: number;
    readonly items: readonly BrowserRequestRuleDecisionRecord[];
    readonly omissions: readonly {
      readonly decision: BrowserRequestRuleDecision;
      readonly count: number;
      readonly reasons: readonly BrowserRequestRuleOmissionReason[];
    }[];
  } {
    return {
      retained: this.#items.length,
      dropped: this.#dropped,
      items: [...this.#items],
      omissions: [...this.#omitted]
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([decision, omission]) => ({
          decision,
          count: omission.count,
          reasons: [...omission.reasons].sort(),
        })),
    };
  }

  #admissionReason(cost: number): BrowserRequestRuleOmissionReason | undefined {
    if (this.#items.length >= BROWSER_MUTATION_LIMITS.maxRuleDecisions)
      return "max-decisions";
    if (
      cost >
      BROWSER_MUTATION_LIMITS.maxRuleDecisionAllocationBytes -
        this.#retainedCost
    )
      return "max-decision-allocation-bytes";
    return undefined;
  }

  #omit(
    decision: BrowserRequestRuleDecision,
    reason: BrowserRequestRuleOmissionReason,
  ): void {
    this.#dropped += 1;
    const omission = this.#omitted.get(decision) ?? {
      count: 0,
      reasons: new Set<BrowserRequestRuleOmissionReason>(),
    };
    omission.count += 1;
    omission.reasons.add(reason);
    this.#omitted.set(decision, omission);
  }
}
