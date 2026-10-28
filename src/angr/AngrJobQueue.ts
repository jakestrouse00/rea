import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { ANGR_PROVIDER_ID } from "../domain/angr/angrLimits.js";
import { err, ok, type Result } from "../domain/result.js";

/** Admission state of one lane, for lifecycle reports and tests. */
export interface AngrJobQueueSnapshot {
  readonly active: number;
  readonly queued: number;
  readonly closed: boolean;
}

interface WaitingJob {
  readonly operation: string;
  readonly signal: AbortSignal | undefined;
  readonly admit: (admission: Result<void, AnalysisError>) => void;
  readonly onAbort: () => void;
}

/**
 * Bounded admission for one symbolic lane.
 *
 * Every bridge job owns one angr process, and angr trades memory for
 * exploration width, so the lane admits a fixed number of jobs at once and
 * holds the rest in arrival order. A caller that cancels while queued leaves
 * the queue without consuming a slot, and a close cancels every waiter and
 * resolves once the admitted jobs have settled.
 */
export class AngrJobQueue {
  readonly #jobs: number;
  readonly #waiting: WaitingJob[] = [];
  readonly #idleWaiters: (() => void)[] = [];
  #active = 0;
  #closed = false;

  constructor(jobs: number) {
    this.#jobs = Math.max(1, Math.trunc(jobs));
  }

  snapshot(): AngrJobQueueSnapshot {
    return {
      active: this.#active,
      queued: this.#waiting.length,
      closed: this.#closed,
    };
  }

  /** Run one task once a slot is free, or refuse the caller's admission. */
  async run<T>(
    operation: string,
    signal: AbortSignal | undefined,
    task: () => Promise<Result<T, AnalysisError>>,
  ): Promise<Result<T, AnalysisError>> {
    const admission = await this.#admit(operation, signal);
    if (!admission.ok) return admission;
    try {
      return await task();
    } finally {
      this.#release();
    }
  }

  /** Cancel every waiter and resolve after the admitted jobs have settled. */
  async close(): Promise<void> {
    this.#closed = true;
    for (const waiter of this.#waiting.splice(0))
      this.#settleWaiter(waiter, this.#cancelled(waiter.operation));
    await this.#idle();
  }

  #admit(
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<void, AnalysisError>> {
    if (this.#closed || signal?.aborted === true)
      return Promise.resolve(
        err(
          new AnalysisCancelledError(operation, {
            cause: this.#closed ? new Error("REA is closing") : signal?.reason,
          }),
        ),
      );
    if (this.#active < this.#jobs && this.#waiting.length === 0) {
      this.#active += 1;
      return Promise.resolve(ok(undefined));
    }
    return new Promise((resolve) => {
      const waiter: WaitingJob = {
        operation,
        signal,
        admit: resolve,
        onAbort: () => {
          const index = this.#waiting.indexOf(waiter);
          if (index < 0) return;
          this.#waiting.splice(index, 1);
          this.#settleWaiter(waiter, this.#cancelled(operation));
        },
      };
      this.#waiting.push(waiter);
      signal?.addEventListener("abort", waiter.onAbort, { once: true });
    });
  }

  #release(): void {
    this.#active -= 1;
    const next = this.#waiting.shift();
    if (next !== undefined) {
      this.#active += 1;
      this.#settleWaiter(next, ok(undefined));
    }
    if (this.#active === 0)
      for (const resolve of this.#idleWaiters.splice(0)) resolve();
  }

  #settleWaiter(
    waiter: WaitingJob,
    admission: Result<void, AnalysisError>,
  ): void {
    waiter.signal?.removeEventListener("abort", waiter.onAbort);
    waiter.admit(admission);
  }

  #cancelled(operation: string): Result<void, AnalysisError> {
    return err(
      new AnalysisCancelledError(operation, {
        cause: new Error(`${ANGR_PROVIDER_ID} admitted no further jobs`),
      }),
    );
  }

  #idle(): Promise<void> {
    if (this.#active === 0) return Promise.resolve();
    return new Promise((resolve) => this.#idleWaiters.push(resolve));
  }
}
