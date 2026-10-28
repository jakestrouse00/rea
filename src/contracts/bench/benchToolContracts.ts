import { runBenchTaskInputSchema } from "./benchInputSchemas.js";
import {
  BENCH_LIMA_PROFILE_ENV,
  BENCH_LIMITS,
  BENCH_OUTCOME_RELATIVE_PATH,
} from "../../domain/bench/benchLimits.js";
import { benchTaskObservationSchema } from "../../domain/bench/benchTask.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

const flagExample =
  "6f1c0f9b2d7e4a5c8b3d1e0f9a2c7b6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b";

/**
 * The benchmark plane: run caller-supplied NYU CTF Bench and Cybench tasks
 * inside the Lima lab VM and report their metric bit.
 *
 * No container runtime, corpus, or VM tooling is supplied here. The lane boots
 * the caller's profile-selected template through the lab-VM lane, runs the
 * caller's entrypoint, and reads the harness's own outcome file.
 */
export const BENCH_TOOL_CONTRACTS = [
  {
    name: "run_bench_task",
    ...toolContractMetadata("run_bench_task"),
    description: `Run one caller-supplied containerized benchmark task inside the caller's Lima lab VM and report whether its declared success metric was met. The process must be started with ${BENCH_LIMA_PROFILE_ENV} set to nyu-ctf-bench or cybench; a task whose suite differs from that profile is refused, and an unset profile is a typed unavailable state. The lane boots one VM with workspace_path mounted at /workspace, runs entrypoint in the guest with the task identity and the outcome path ${BENCH_OUTCOME_RELATIVE_PATH} exported, then reads that file on the host and removes the instance. A flag task succeeds when the recovered flag hashes to expected_flag_sha256; a POV task succeeds when the harness recorded a proof-of-vulnerability bit, optionally naming the expected sanitizer class. Neither the expected nor the recovered flag value is published: only digests and structural facts become Evidence. A command REA stops at budget_seconds (default ${String(BENCH_LIMITS.defaultTaskSeconds)}, at most ${String(BENCH_LIMITS.maxTaskSeconds)}) reports budget_exhausted, and a missing, oversized, or unparseable outcome file is an unknown outcome state, never a claim that the task was unsolved. REA downloads no benchmark corpus, container image, or container runtime; one lab VM is live per process, so a failed stop keeps the lab-VM identity for a stop_lab_vm retry and the result reports vm.stopped false.`,
    kind: "benchmark-harness",
    inputSchema: runBenchTaskInputSchema,
    outputSchema: evidenceResultOf(benchTaskObservationSchema),
    examples: [
      {
        title: "Score a flag task against its expected digest",
        input: {
          task_id: "nyu-ctf-bench/web-01",
          suite: "nyu-ctf-bench",
          workspace_path: "/cases/bench/web-01",
          entrypoint: "docker compose up --abort-on-container-exit harness",
          success: { kind: "flag", expected_flag_sha256: flagExample },
          budget_seconds: 600,
        },
      },
      {
        title: "Score a Cybench task by its recorded POV bit",
        input: {
          task_id: "cybench/crypto-07",
          suite: "cybench",
          workspace_path: "/cases/bench/crypto-07",
          entrypoint: "./run-task.sh",
          success: { kind: "pov", expected_sanitizer: "address" },
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
