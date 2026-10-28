import {
  cancelHuntingBatchInputSchema,
  readHuntingQueueInputSchema,
  runScheduledBatchInputSchema,
  scheduleInvestigationBatchInputSchema,
  startWatchSessionInputSchema,
  stopWatchSessionInputSchema,
} from "./huntingInputSchemas.js";
import {
  huntingCancelResultSchema,
  huntingQueueReadResultSchema,
  huntingRunResultSchema,
  huntingScheduleResultSchema,
  huntingWatchStartResultSchema,
  huntingWatchStopResultSchema,
} from "../../domain/hunting/huntingObservation.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

const batchIdExample = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const targetExample = "/cases/api/target.bin";

/**
 * The orchestration plane: queue analysis work, admit it one unit at a time,
 * and watch a directory for changes that enqueue more.
 *
 * No recipe is executed here. Each unit delegates to the capability that owns
 * the work, so the queue adds ordering, budgets, and durable state, not a
 * second analyzer.
 */
export const HUNTING_TOOL_CONTRACTS = [
  {
    name: "schedule_investigation_batch",
    ...toolContractMetadata("schedule_investigation_batch"),
    description:
      "Queue a durable batch of analysis units: every target in targets is paired with every recipe in recipes. Each target carries an optional completion ledger and residual-unknown identities, which order the units (failing, truncated, and unknown claims plus unresolved unknown severity raise a unit; a missing ledger is unknown coverage, never complete). Recipe kinds this release can queue are re-analysis (repeat binary_overview, list_procedures, or list_strings over the server's admitted analysis target), fuzz-campaign (admit a registered campaign through the fuzz loop), probe (probe a learned protocol model against one operator-allowlisted loopback socket through the protocol-learning lane), and replay (re-send one captured entry through an existing replay or interception session). The batch is written to an owner-only SQLite queue under the REA home state directory before this call returns, so a restarted REA resumes the same units. Nothing is admitted here; call run_scheduled_batch to admit the next unit.",
    kind: "hunting-queue",
    inputSchema: scheduleInvestigationBatchInputSchema,
    outputSchema: evidenceResultOf(huntingScheduleResultSchema),
    examples: [
      {
        title: "Queue one re-analysis per target",
        input: {
          targets: [{ path: targetExample }],
          recipes: [{ kind: "re-analysis", operation: "binary_overview" }],
        },
      },
      {
        title: "Queue a probe after a re-analysis with a bounded budget",
        input: {
          targets: [{ path: targetExample }],
          recipes: [
            { kind: "re-analysis", operation: "list_procedures" },
            {
              kind: "probe",
              endpoint: { host: "127.0.0.1", port: 9000 },
              model_path: "/cases/api/protocol/model.json",
              probes: [
                {
                  label: "hello",
                  steps: [{ template_hex: "0100", wait_for_response: true }],
                },
              ],
            },
          ],
          budget: { max_units: 2, max_seconds: 600 },
        },
      },
    ],
  },
  {
    name: "run_scheduled_batch",
    ...toolContractMetadata("run_scheduled_batch"),
    description:
      "Admit the next unit of one batch (or of the oldest runnable batch) and record its outcome before replying. Queued units are admitted before blocked ones; a blocked unit reports a named precondition and is retried after every queued unit. The unit runs under the tighter of max_unit_seconds and the hunting.max_unit_seconds setting; a unit that reaches its deadline, or a batch that reaches its unit or wall-clock budget, ends with a typed stop and stays queued, so no work is lost and no unit is retried automatically. The composed capability's observation is retained as its own Evidence and named by identity and canonical result digest; this lane starts no subprocess of its own, and it reports when REA_DISABLE_SANDBOX leaves the composed launches unconfined. A unit that does not complete records one residual unknown scoped to its own unit Evidence.",
    kind: "hunting-queue",
    inputSchema: runScheduledBatchInputSchema,
    outputSchema: evidenceResultOf(huntingRunResultSchema),
    examples: [
      { title: "Admit the next unit of the oldest batch", input: {} },
      {
        title: "Admit one unit of a chosen batch with a short deadline",
        input: { batch_id: batchIdExample, max_unit_seconds: 60 },
      },
    ],
  },
  {
    name: "read_hunting_queue",
    ...toolContractMetadata("read_hunting_queue"),
    description:
      "Report the durable queue without admitting anything: every batch with its state and budget, and one page of units in queue order with their state, attempt count, and ordering reasons. Read-only; no Evidence is recorded and no unit changes state. The page reports counts for the whole queue so a caller can see what remains after a budget stop.",
    kind: "hunting-queue",
    inputSchema: readHuntingQueueInputSchema,
    outputSchema: huntingQueueReadResultSchema,
    examples: [
      { title: "Read the first page across every batch", input: {} },
      {
        title: "Page one batch's units",
        input: { batch_id: batchIdExample, offset: 10, limit: 10 },
      },
    ],
  },
  {
    name: "cancel_hunting_batch",
    ...toolContractMetadata("cancel_hunting_batch"),
    description:
      "Release every unit of one batch that has not started and mark the batch cancelled. A unit already admitted is not interrupted by this call; it finishes and records its own outcome, which the result counts as in flight. Cancelling an already-cancelled batch changes nothing and reports zero released units.",
    kind: "hunting-queue",
    inputSchema: cancelHuntingBatchInputSchema,
    outputSchema: evidenceResultOf(huntingCancelResultSchema),
    examples: [
      { title: "Cancel one batch", input: { batch_id: batchIdExample } },
    ],
  },
  {
    name: "start_watch_session",
    ...toolContractMetadata("start_watch_session"),
    description:
      "Observe one directory tree and enqueue re-analysis for one investigation target whenever the tree changes. The session answers with a session_id and keeps a bounded entry-only snapshot (name, size, modification time; no file content, and symbolic links are never followed); each interval reads the tree again and enqueues one re-analysis unit per observed change into a batch the session owns, up to max_triggers. A change tick that is still pending is not overlapped. The session ends at its trigger budget; stop_watch_session releases it earlier. This release watches a directory only: a device or endpoint source is refused with a typed unavailable state. A watch never analyzes anything itself, so no unit is admitted without a run_scheduled_batch call.",
    kind: "hunting-queue",
    inputSchema: startWatchSessionInputSchema,
    outputSchema: evidenceResultOf(huntingWatchStartResultSchema),
    examples: [
      {
        title: "Watch a build directory for one target",
        input: {
          source: { kind: "directory", path: "/cases/api/build" },
          target: { path: targetExample },
          interval_ms: 5000,
          max_triggers: 8,
        },
      },
    ],
  },
  {
    name: "stop_watch_session",
    ...toolContractMetadata("stop_watch_session"),
    description:
      "Release one watch session: clear its owned timer, abort an in-flight directory read, and wait for it to settle. Units the session already queued stay in its batch; cancelling that batch is a separate call. A failed release keeps the session identity so this tool can be retried, and a cancellation that arrives while the release finishes returns typed cancellation with the partial observation of what was released.",
    kind: "hunting-queue",
    inputSchema: stopWatchSessionInputSchema,
    outputSchema: evidenceResultOf(huntingWatchStopResultSchema),
    examples: [
      {
        title: "Release one watch session",
        input: { session_id: "2f1c9d4e-0b6a-4c8f-9e37-5a1f0d2b7c33" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
