import { z } from "zod";

import { LAB_VM_COMMAND_ENV } from "../vmlab/labVm.js";

/** Provider identity for the benchmark harness lane. */
export const BENCH_PROVIDER = {
  id: "rea-bench",
  name: "REA benchmark harness",
  version: "1",
} as const;

/** Benchmark profile this REA process may run inside the lab VM. */
export const BENCH_LIMA_PROFILE_ENV = "REA_BENCH_LIMA_PROFILE";

export const BENCH_LIMA_PROFILE_REMEDIATION = `Set ${BENCH_LIMA_PROFILE_ENV} to nyu-ctf-bench or cybench in the launch environment and restart REA. The profile names the caller-supplied Lima template this lane boots through ${LAB_VM_COMMAND_ENV}; REA downloads neither the benchmark corpus, its container images, nor a container runtime.`;

/** Containerized benchmark suites this release can drive. */
export const BENCH_PROFILES = ["nyu-ctf-bench", "cybench"] as const;

export const benchProfileSchema = z.enum(BENCH_PROFILES);

export type BenchProfile = z.infer<typeof benchProfileSchema>;

export const BENCH_LIMITS = {
  /** Longest wall clock one task command may run on the guest clock. */
  maxTaskSeconds: 7_200,
  /** Wall clock applied when the caller omits `budget_seconds`. */
  defaultTaskSeconds: 900,
  /** Retained bytes of the harness outcome file. */
  maxOutcomeBytes: 1024 * 1024,
  /** Characters of one caller-supplied task identity. */
  maxTaskIdCharacters: 128,
  /** Bytes of one caller-supplied guest entrypoint command line. */
  maxEntrypointBytes: 4_096,
} as const;

/** Workspace-relative path where the guest harness writes its outcome. */
export const BENCH_OUTCOME_RELATIVE_PATH = ".rea-bench/outcome.json";

/** Environment the lane exports to the guest harness before its entrypoint. */
export const BENCH_TASK_ID_ENV = "REA_BENCH_TASK_ID";

/** Guest path the harness must write its outcome to. */
export const BENCH_OUTCOME_ENV = "REA_BENCH_OUTCOME_PATH";

/** How the metric is established, and what it does not establish. */
export const BENCH_METRIC_LIMITATION =
  "A succeeded task reports the metric its own harness declared: a recovered flag whose SHA-256 matches the expected digest, or a proof of vulnerability the harness recorded. REA compares digests and reads the recorded POV bit; it does not independently reproduce the exploit or attest that the harness ran the task honestly.";

/** A missing outcome is unknown, never a clean failure. */
export const BENCH_OUTCOME_LIMITATION = `The guest harness writes its outcome to ${BENCH_OUTCOME_RELATIVE_PATH} in the workspace. A task command that exits without that file, or writes one this release cannot parse, is reported as unknown outcome state; neither proves the task was unsolved.`;

/** The corpus and container images stay caller-owned. */
export const BENCH_CORPUS_LIMITATION =
  "The benchmark corpus, container images, harness, and expected flag digests are caller-supplied. REA downloads no NYU CTF Bench or Cybench task and runs no container runtime of its own; the entrypoint is a command the caller selected inside the guest.";

/** The guest is a complete operating system, not a sandboxed child. */
export const BENCH_GUEST_LIMITATION =
  "Each run boots one lab VM from the selected profile, runs the entrypoint, reads the outcome, and removes the instance. Only one lab VM is live per REA process, so a run fails when another caller already owns one.";

export const BENCH_UNVERIFIED_NOTE =
  "This lane is exercised with a scripted limactl stand-in only; the offline suite boots no real Lima VM and runs no containerized benchmark task.";
