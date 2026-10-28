import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type {
  LabVmPort,
  LabVmRunRequest,
  LabVmStartRequest,
  LabVmStopRequest,
} from "../application/vmlab/LabVmPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { BENCH_LIMITS, BENCH_PROVIDER } from "../domain/bench/benchLimits.js";
import {
  benchTaskObservationSchema,
  type BenchSuccessMetric,
} from "../domain/bench/benchTask.js";
import type { Evidence } from "../domain/evidence.js";
import { err, ok } from "../domain/result.js";
import type { LabVmCommandResult } from "../domain/vmlab/labVmObservation.js";
import {
  createLabVmCommandEvidence,
  createLabVmStartEvidence,
  createLabVmStopEvidence,
} from "../vmlab/LabVmEvidence.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { BenchTaskAdapter } from "./BenchTaskAdapter.js";

const sessionId = "2f1c9d4e-0b6a-4c8f-9e37-5a1f0d2b7c33";
const workspaceFixture = "/cases/bench/web-01";
const flag = "flag{synthetic-bench-fixture}";
const flagSha256 = createHash("sha256").update(flag, "utf8").digest("hex");

const available: ProviderAvailability = {
  status: "available",
  code: null,
  reason: null,
  diagnostics: { selected_command: "/opt/homebrew/bin/limactl" },
};

interface Script {
  readonly availability?: ProviderAvailability;
  readonly outcome?: unknown;
  readonly rawOutcome?: string;
  readonly guest?: Partial<LabVmCommandResult>;
  readonly startFailure?: AnalysisError;
  readonly runFailure?: AnalysisError;
  readonly stopFailure?: AnalysisError;
}

interface FakeLabVm extends LabVmPort {
  readonly starts: LabVmStartRequest[];
  readonly runs: LabVmRunRequest[];
  readonly stops: LabVmStopRequest[];
  readonly commands: string[];
}

const commandResult = (
  overrides: Partial<LabVmCommandResult> = {},
): LabVmCommandResult => ({
  session_id: sessionId,
  command: "cd /workspace",
  exit_type: "exited",
  exit_code: 0,
  duration_ms: 1_200,
  timeout_ms: 600_000,
  stdout_bytes: 0,
  stderr_bytes: 0,
  output_truncated: false,
  produced_paths: [".rea-bench/outcome.json"],
  modified_paths: [],
  removed_paths: [],
  changes_truncated: false,
  ...overrides,
});

const fakeLabVm = (workspace: string, script: Script): FakeLabVm => {
  const starts: LabVmStartRequest[] = [];
  const runs: LabVmRunRequest[] = [];
  const stops: LabVmStopRequest[] = [];
  const commands: string[] = [];
  return {
    defaultCommandTimeoutMs: 1_000,
    starts,
    runs,
    stops,
    commands,
    inspectAvailability: () => script.availability ?? available,
    start: async (request) => {
      starts.push(request);
      if (script.startFailure !== undefined) return err(script.startFailure);
      return ok(
        createLabVmStartEvidence(
          {},
          {
            session_id: sessionId,
            vm_name: "rea-lab-fixture",
            workspace_path: workspace,
            guest_workspace: "/workspace",
            driver: "vz",
            rosetta: true,
            boot: { exit_type: "exited", exit_code: 0, duration_ms: 2_000 },
          },
          [],
        ),
      );
    },
    run: async (request) => {
      runs.push(request);
      commands.push(request.command);
      if (script.runFailure !== undefined) return err(script.runFailure);
      if (script.outcome !== undefined || script.rawOutcome !== undefined) {
        await mkdir(join(workspace, ".rea-bench"), { recursive: true });
        await writeFile(
          join(workspace, ".rea-bench/outcome.json"),
          script.rawOutcome ?? JSON.stringify(script.outcome),
        );
      }
      return ok(
        createLabVmCommandEvidence(
          {},
          workspace,
          commandResult(script.guest),
          [],
        ),
      );
    },
    stop: async (request) => {
      stops.push(request);
      if (script.stopFailure !== undefined) return err(script.stopFailure);
      return ok(
        createLabVmStopEvidence(
          {},
          {
            session_id: sessionId,
            vm_name: "rea-lab-fixture",
            stop: { exit_type: "exited", exit_code: 0, duration_ms: 500 },
            deleted: true,
          },
          [],
        ),
      );
    },
    closeAll: async () => ok(null),
  };
};

const request = (
  success: BenchSuccessMetric,
  overrides: Partial<{
    taskId: string;
    suite: "nyu-ctf-bench" | "cybench";
    workspacePath: string;
    entrypoint: string;
    budgetSeconds: number;
  }> = {},
) => ({
  taskId: "nyu-ctf-bench/web-01",
  suite: "nyu-ctf-bench" as const,
  workspacePath: workspaceFixture,
  entrypoint: "docker compose up --abort-on-container-exit harness",
  success,
  budgetSeconds: 600,
  ...overrides,
});

const flagMetric = (expected: string = flagSha256): BenchSuccessMetric => ({
  kind: "flag",
  expected_flag_sha256: expected,
});

const run = async (
  script: Script,
  success: BenchSuccessMetric = flagMetric(),
  overrides: Parameters<typeof request>[1] = {},
  environment: Readonly<Record<string, string | undefined>> = {
    REA_BENCH_LIMA_PROFILE: "nyu-ctf-bench",
  },
) => {
  const workspace = await createTestTempDirectory("rea-bench-");
  const labVm = fakeLabVm(workspace, script);
  const adapter = new BenchTaskAdapter({ environment, labVm });
  const result = await adapter.run(
    request(success, { ...overrides, workspacePath: workspace }),
  );
  return { result, labVm, workspace };
};

const observationOf = (evidence: Evidence) =>
  benchTaskObservationSchema.parse(evidence.normalized_result);

describe("benchmark task adapter", () => {
  it("scores a recovered flag without publishing its value", async () => {
    const { result, labVm } = await run({
      outcome: { status: "completed", flag },
    });
    if (!result.ok) throw result.error;
    expect(observationOf(result.value)).toMatchObject({
      task_id: "nyu-ctf-bench/web-01",
      suite: "nyu-ctf-bench",
      status: "succeeded",
      outcome_state: "read",
      budget_seconds: 600,
      metric: {
        kind: "flag",
        satisfied: true,
        reason: null,
        recovered_flag_sha256: flagSha256,
      },
      vm: { stopped: true },
    });
    expect(JSON.stringify(result.value)).not.toContain(flag);
    expect(result.value.provider).toEqual(BENCH_PROVIDER);
    expect(result.value.limitations).toContainEqual(
      expect.stringContaining("does not independently reproduce"),
    );
    expect(labVm.starts).toHaveLength(1);
    expect(labVm.runs[0]?.timeoutMs).toBe(600_000);
    expect(labVm.commands[0]).toContain(
      "REA_BENCH_TASK_ID='nyu-ctf-bench/web-01'",
    );
    expect(labVm.commands[0]).toContain(
      "REA_BENCH_OUTCOME_PATH='/workspace/.rea-bench/outcome.json'",
    );
    expect(labVm.commands[0]).toContain("cd '/workspace'");
    expect(labVm.stops).toEqual([{ sessionId }]);
  });

  it("reports a mismatched flag as unsatisfied with its digest", async () => {
    const { result } = await run({
      outcome: { status: "completed", flag: "flag{wrong}" },
    });
    if (!result.ok) throw result.error;
    const observation = observationOf(result.value);
    expect(observation.status).toBe("unsatisfied");
    expect(observation.metric).toMatchObject({
      satisfied: false,
      reason: "flag_mismatch",
      recovered_flag_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
    });
    expect(observation.metric.recovered_flag_sha256).not.toBe(flagSha256);
  });

  it("reports a POV bit and its sanitizer class", async () => {
    const { result } = await run(
      {
        outcome: {
          status: "completed",
          pov: { recorded: true, sanitizer_class: "address" },
        },
      },
      { kind: "pov" },
      { suite: "nyu-ctf-bench" },
    );
    if (!result.ok) throw result.error;
    expect(observationOf(result.value)).toMatchObject({
      status: "succeeded",
      metric: {
        kind: "pov",
        satisfied: true,
        sanitizer_class: "address",
      },
    });
  });

  it("treats a missing outcome as unknown rather than unsolved", async () => {
    const { result } = await run({});
    if (!result.ok) throw result.error;
    const observation = observationOf(result.value);
    expect(observation).toMatchObject({
      status: "unsatisfied",
      outcome_state: "missing",
      metric: { satisfied: false, reason: "outcome_missing" },
    });
    expect(result.value.limitations).toContainEqual(
      expect.stringContaining("No outcome file was written"),
    );
  });

  it("refuses an outcome larger than the retained budget", async () => {
    const { result } = await run({
      rawOutcome: `{"status":"completed"}${" ".repeat(BENCH_LIMITS.maxOutcomeBytes)}`,
    });
    if (!result.ok) throw result.error;
    expect(observationOf(result.value)).toMatchObject({
      outcome_state: "oversized",
      metric: { reason: "outcome_oversized" },
    });
  });

  it("refuses an outcome this release cannot parse", async () => {
    const { result } = await run({ rawOutcome: "not json" });
    if (!result.ok) throw result.error;
    expect(observationOf(result.value)).toMatchObject({
      outcome_state: "unreadable",
      metric: { reason: "outcome_unreadable" },
    });
  });

  it("lets a guest deadline outrank a stray matched outcome", async () => {
    const { result } = await run({
      outcome: { status: "completed", flag },
      guest: { exit_type: "timeout", exit_code: null, timeout_ms: 600_000 },
    });
    if (!result.ok) throw result.error;
    expect(observationOf(result.value)).toMatchObject({
      status: "budget_exhausted",
      metric: { satisfied: true, reason: null },
      guest: { exit_type: "timeout" },
    });
  });

  it("clamps the declared budget to the retained maximum", async () => {
    const { result, labVm } = await run(
      { outcome: { status: "completed", flag } },
      flagMetric(),
      { budgetSeconds: BENCH_LIMITS.maxTaskSeconds + 1_000 },
    );
    if (!result.ok) throw result.error;
    expect(observationOf(result.value).budget_seconds).toBe(
      BENCH_LIMITS.maxTaskSeconds,
    );
    expect(labVm.runs[0]?.timeoutMs).toBe(BENCH_LIMITS.maxTaskSeconds * 1_000);
  });
});

describe("benchmark task adapter refusals and lifecycle", () => {
  it("refuses an unset profile with typed remediation", async () => {
    const { result, labVm } = await run(
      { outcome: { status: "completed", flag } },
      flagMetric(),
      {},
      {},
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a refusal");
    expect(result.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    expect(result.error.diagnostics).toMatchObject({
      setting: "REA_BENCH_LIMA_PROFILE",
    });
    expect(labVm.starts).toHaveLength(0);
  });

  it("refuses a task whose suite is not the selected profile", async () => {
    const { result, labVm } = await run(
      { outcome: { status: "completed", flag } },
      flagMetric(),
      { suite: "cybench" },
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a refusal");
    expect(result.error).toBeInstanceOf(AnalysisInputError);
    expect((result.error as AnalysisInputError).issues[0]).toMatchObject({
      path: ["suite"],
      reason: "invalid_value",
    });
    expect(labVm.starts).toHaveLength(0);
  });

  it("refuses before booting when the lab-VM lane is unavailable", async () => {
    const { result, labVm } = await run({
      availability: {
        status: "unavailable",
        code: "executable_missing",
        reason: "The selected limactl binary was not found",
        diagnostics: {},
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a refusal");
    expect(result.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    expect(result.error.message).toContain("limactl");
    expect(labVm.starts).toHaveLength(0);
  });

  it("keeps the instance identity when the stop fails", async () => {
    const { result, labVm } = await run({
      outcome: { status: "completed", flag },
      stopFailure: new AnalysisCapabilityUnavailableError(
        BENCH_PROVIDER.id,
        "stop_lab_vm",
        "The guest did not stop",
      ),
    });
    if (!result.ok) throw result.error;
    expect(observationOf(result.value).vm).toEqual({ stopped: false });
    expect(result.value.limitations).toContainEqual(
      expect.stringContaining("stop_lab_vm must be retried"),
    );
    expect(labVm.stops).toHaveLength(1);
  });

  it("releases the VM and returns the failure when the command fails", async () => {
    const failure = new AnalysisCancelledError("run_lab_vm_command");
    const { result, labVm } = await run({ runFailure: failure });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a failure");
    expect(result.error).toBe(failure);
    expect(labVm.stops).toEqual([{ sessionId }]);
  });

  it("reports the profile and lab-VM readiness without booting", async () => {
    const workspace = await createTestTempDirectory("rea-bench-");
    const adapter = new BenchTaskAdapter({
      environment: { REA_BENCH_LIMA_PROFILE: "cybench" },
      labVm: fakeLabVm(workspace, {}),
    });
    expect(adapter.inspectAvailability()).toMatchObject({
      status: "available",
      diagnostics: { profile: "cybench" },
    });
    expect(
      new BenchTaskAdapter({
        environment: {},
        labVm: fakeLabVm(workspace, {}),
      }).inspectAvailability(),
    ).toMatchObject({ status: "unavailable", code: "not_configured" });
  });

  it("preserves a failed start without stopping an unissued session", async () => {
    const failure = new AnalysisCapabilityUnavailableError(
      BENCH_PROVIDER.id,
      "start_lab_vm",
      "No guest image",
    );
    const { result, labVm } = await run({ startFailure: failure });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a failure");
    expect(result.error).toBe(failure);
    expect(labVm.stops).toHaveLength(0);
  });
});
