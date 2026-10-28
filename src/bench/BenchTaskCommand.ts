import { posix } from "node:path";

import type { BenchTaskDescriptor } from "../domain/bench/benchTask.js";
import {
  BENCH_OUTCOME_ENV,
  BENCH_OUTCOME_RELATIVE_PATH,
  BENCH_TASK_ID_ENV,
} from "../domain/bench/benchLimits.js";
import { LAB_VM_GUEST_WORKSPACE } from "../domain/vmlab/labVm.js";

const shellQuote = (value: string): string =>
  `'${value.replaceAll("'", `'\\''`)}'`;

/**
 * Build the one guest command line that runs a benchmark task.
 *
 * The task's own entrypoint stays the caller's command. This wrapper only
 * pins the guest working directory, publishes the task identity and outcome
 * path the harness reads, and creates the outcome directory, because `limactl
 * shell` receives the whole line as a single argv element and runs it through
 * the guest shell.
 */
export const benchGuestCommand = (task: BenchTaskDescriptor): string => {
  const outcomePath = posix.join(
    LAB_VM_GUEST_WORKSPACE,
    BENCH_OUTCOME_RELATIVE_PATH,
  );
  return [
    `cd ${shellQuote(LAB_VM_GUEST_WORKSPACE)}`,
    `export ${BENCH_TASK_ID_ENV}=${shellQuote(task.taskId)} ${BENCH_OUTCOME_ENV}=${shellQuote(outcomePath)}`,
    `mkdir -p ${shellQuote(posix.dirname(outcomePath))}`,
    task.entrypoint,
  ].join(" && ");
};
