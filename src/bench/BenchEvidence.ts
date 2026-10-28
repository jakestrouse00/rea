import { createEvidence, type Evidence } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  BENCH_CORPUS_LIMITATION,
  BENCH_GUEST_LIMITATION,
  BENCH_METRIC_LIMITATION,
  BENCH_OUTCOME_LIMITATION,
  BENCH_PROVIDER,
  BENCH_UNVERIFIED_NOTE,
} from "../domain/bench/benchLimits.js";
import { benchTaskObservationSchema } from "../domain/bench/benchTask.js";
import {
  LAB_VM_GUEST_ARCHITECTURE,
  LAB_VM_DRIVER,
} from "../domain/vmlab/labVm.js";

const environment = {
  id: `${LAB_VM_DRIVER}-${LAB_VM_GUEST_ARCHITECTURE}`,
  platform: "linux",
  architecture: LAB_VM_GUEST_ARCHITECTURE,
  isolation: "virtual-machine",
} as const;

/** Evidence for one benchmark task run, with its metric bit and no flag value. */
export const createBenchTaskEvidence = (
  parameters: Readonly<Record<string, JsonValue>>,
  workspacePath: string,
  result: unknown,
  limitations: readonly string[],
): Evidence => {
  const parsed = benchTaskObservationSchema.parse(result);
  return createEvidence(undefined, BENCH_PROVIDER, {
    predicateType: "benchmark-task",
    operation: "run_bench_task",
    parameters,
    result: parsed,
    confidence: "observed",
    authority: "controlled-replay",
    environment,
    limitations: [
      ...limitations,
      BENCH_METRIC_LIMITATION,
      BENCH_OUTCOME_LIMITATION,
      BENCH_CORPUS_LIMITATION,
      BENCH_GUEST_LIMITATION,
      BENCH_UNVERIFIED_NOTE,
    ],
    locations: [{ kind: "artifact-path", path: workspacePath }],
    subjectUnavailableReason:
      "A benchmark task is a caller-supplied workspace and container image, not one analysis-target artifact.",
  });
};
