import type { BenchTaskPort } from "../application/bench/BenchTaskPort.js";
import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import { BenchTaskAdapter } from "../bench/BenchTaskAdapter.js";

/** Compose the benchmark harness over the caller-selected lab-VM lane. */
export const createBenchTaskService = (
  environment: Readonly<Record<string, string | undefined>>,
  labVm: LabVmPort,
): BenchTaskPort => new BenchTaskAdapter({ environment, labVm });
