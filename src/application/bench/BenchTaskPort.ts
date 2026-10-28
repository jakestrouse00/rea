import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { BenchSuccessMetric } from "../../domain/bench/benchTask.js";
import type { BenchProfile } from "../../domain/bench/benchLimits.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";

/** One caller-supplied benchmark task, in the caller's own vocabulary. */
export interface RunBenchTaskRequest {
  readonly taskId: string;
  readonly suite: BenchProfile;
  /** Host directory the lab VM mounts at /workspace. */
  readonly workspacePath: string;
  /** Guest command that runs the containerized task from /workspace. */
  readonly entrypoint: string;
  readonly success: BenchSuccessMetric;
  readonly budgetSeconds: number;
}

/**
 * The benchmark harness seam.
 *
 * One call boots a lab VM from the selected profile, runs the caller's task
 * command, reads the harness outcome, releases the VM, and reports the metric
 * bit as Evidence. The lane owns no virtual machine and no container runtime of
 * its own: VM lifecycle is the lab-VM lane's, and the task image is the
 * caller's.
 */
export interface BenchTaskPort {
  /** Report the selected profile and the lab-VM lane's readiness without booting. */
  inspectAvailability(signal?: AbortSignal): ProviderAvailability;
  run(
    request: RunBenchTaskRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
}
