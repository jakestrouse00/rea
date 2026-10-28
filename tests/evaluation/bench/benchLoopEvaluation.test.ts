import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { BenchTaskAdapter } from "../../../src/bench/BenchTaskAdapter.js";
import type {
  LabVmPort,
  LabVmRunRequest,
  LabVmStartRequest,
  LabVmStopRequest,
} from "../../../src/application/vmlab/LabVmPort.js";
import type { ProviderAvailability } from "../../../src/application/AnalysisProvider.js";
import { protocolModelSchema } from "../../../src/domain/protolearn/protocolModel.js";
import { ok } from "../../../src/domain/result.js";
import {
  createLabVmCommandEvidence,
  createLabVmStartEvidence,
  createLabVmStopEvidence,
} from "../../../src/vmlab/LabVmEvidence.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  createBenchLoopFixture,
  writeBenchOutcome,
} from "./BenchLoopFixtures.js";
import {
  evidenceContainsValue,
  loopMetricsSatisfied,
  scoreFuzzingLoop,
  scoreMitmLoop,
  scoreProtolearnLoop,
} from "./BenchLoopMetrics.js";
import {
  buildProtocolModel,
  scriptedFuzzingCampaign,
  scriptedMitm,
  scriptedProtocolLearning,
} from "./BenchLoopScripts.js";

const labVmSessionId = "5b0c6a2e-1f3d-4c8a-9e7b-2d4f3a1c0b95";

const available: ProviderAvailability = {
  status: "available",
  code: null,
  reason: null,
  diagnostics: {},
};

const scriptedLabVm = (workspace: string, outcome: unknown): LabVmPort => {
  const starts: LabVmStartRequest[] = [];
  const runs: LabVmRunRequest[] = [];
  const stops: LabVmStopRequest[] = [];
  return {
    defaultCommandTimeoutMs: 1_000,
    inspectAvailability: () => available,
    start: async (request) => {
      starts.push(request);
      return ok(
        createLabVmStartEvidence(
          {},
          {
            session_id: labVmSessionId,
            vm_name: "rea-lab-eval",
            workspace_path: workspace,
            guest_workspace: "/workspace",
            driver: "vz",
            rosetta: true,
            boot: { exit_type: "exited", exit_code: 0, duration_ms: 1_000 },
          },
          [],
        ),
      );
    },
    run: async (request) => {
      runs.push(request);
      await writeBenchOutcome(workspace, outcome);
      return ok(
        createLabVmCommandEvidence(
          {},
          workspace,
          {
            session_id: labVmSessionId,
            command: request.command,
            exit_type: "exited",
            exit_code: 0,
            duration_ms: 900,
            timeout_ms: request.timeoutMs,
            stdout_bytes: 0,
            stderr_bytes: 0,
            output_truncated: false,
            produced_paths: [".rea-bench/outcome.json"],
            modified_paths: [],
            removed_paths: [],
            changes_truncated: false,
          },
          [],
        ),
      );
    },
    stop: async (request) => {
      stops.push(request);
      return ok(
        createLabVmStopEvidence(
          {},
          {
            session_id: labVmSessionId,
            vm_name: "rea-lab-eval",
            stop: { exit_type: "exited", exit_code: 0, duration_ms: 100 },
            deleted: true,
          },
          [],
        ),
      );
    },
    closeAll: async () => ok(null),
  };
};

describe("Loop A: fuzzing lane metrics", () => {
  it("scores a POV bit and the declared campaign budget", async () => {
    const lane = scriptedFuzzingCampaign({
      acceptedPovs: 2,
      declaredSeconds: 600,
      consumedSeconds: 540,
    });
    const started = await lane.startCampaign({
      campaignId: "3f0f7f8e-6a3c-4c47-9c8e-0f4b5d6a7c81",
      engine: "libfuzzer",
      povRepeats: 2,
      expectedSanitizer: undefined,
      minimizeCrashes: false,
      labVm: null,
    });
    if (!started.ok) throw started.error;
    const { pov, budget } = scoreFuzzingLoop(started.value);
    expect(pov).toMatchObject({
      kind: "pov_bit",
      satisfied: true,
      acceptedPovs: 2,
    });
    expect(budget).toMatchObject({
      kind: "campaign_budget",
      satisfied: true,
      declaredSeconds: 600,
      consumedSeconds: 540,
      bound: "declared",
    });
    expect(loopMetricsSatisfied([pov, budget])).toBe(true);
    expect(lane.requests).toHaveLength(1);
  });

  it("refuses a run that overran its declared budget", async () => {
    const lane = scriptedFuzzingCampaign({
      acceptedPovs: 1,
      declaredSeconds: 300,
      consumedSeconds: 301,
    });
    const started = await lane.startCampaign({
      campaignId: "3f0f7f8e-6a3c-4c47-9c8e-0f4b5d6a7c81",
      engine: "aflpp_frida",
      povRepeats: 1,
      expectedSanitizer: undefined,
      minimizeCrashes: false,
      labVm: null,
    });
    if (!started.ok) throw started.error;
    const { pov, budget } = scoreFuzzingLoop(started.value);
    expect(pov.satisfied).toBe(true);
    expect(budget.satisfied).toBe(false);
    expect(loopMetricsSatisfied([pov, budget])).toBe(false);
  });
});

describe("Loop B: protocol-learning lane metrics", () => {
  it("scores a protocol model the lane exported to the caller's store", async () => {
    const root = await createTestTempDirectory("rea-bench-loop-b-");
    const fixture = await createBenchLoopFixture(root);
    const model = buildProtocolModel(fixture.modelStore, {
      path: fixture.qlog,
      sha256: fixture.qlogSha256,
    });
    const lane = scriptedProtocolLearning(model);
    const learned = await lane.execute({
      operation: "learn_protocol_model",
      input: {
        source: { kind: "qlog", path: fixture.qlog },
        max_states: 8,
        suffix_length: 0,
        sensitive_values: [],
      },
    });
    if (!learned.ok) throw learned.error;
    const exported = protocolModelSchema.parse(
      JSON.parse(await readFile(fixture.modelFile, "utf8")),
    );
    const score = scoreProtolearnLoop(learned.value.result, exported);
    expect(score).toMatchObject({
      kind: "protocol_model_exported",
      satisfied: true,
      classCount: 1,
      stateCount: 1,
      modelFile: fixture.modelFile,
    });
    expect(lane.requests).toHaveLength(1);
    expect(JSON.stringify(learned.value)).not.toContain("qlog_version");
  });

  it("does not claim an export when the learner wrote no store", async () => {
    const root = await createTestTempDirectory("rea-bench-loop-b-");
    const fixture = await createBenchLoopFixture(root);
    const model = buildProtocolModel(null, {
      path: fixture.qlog,
      sha256: fixture.qlogSha256,
    });
    const lane = scriptedProtocolLearning(model);
    const learned = await lane.execute({
      operation: "learn_protocol_model",
      input: {
        source: { kind: "qlog", path: fixture.qlog },
        max_states: 8,
        suffix_length: 0,
        sensitive_values: [],
      },
    });
    if (!learned.ok) throw learned.error;
    expect(scoreProtolearnLoop(learned.value.result, null)).toMatchObject({
      kind: "protocol_model_exported",
      satisfied: false,
      classCount: 0,
      modelFile: null,
    });
  });
});

describe("Loop C: interception lane metrics", () => {
  it("finds the flag in a captured body without publishing it", async () => {
    const root = await createTestTempDirectory("rea-bench-loop-c-");
    const fixture = await createBenchLoopFixture(root);
    const lane = scriptedMitm({
      captureDirectory: fixture.captureDirectory,
      origin: "http://lab.example.test",
      pathTemplate: "/session/:id",
      bodiesHeld: 1,
    });
    const started = await lane.start({
      targetApp: "other",
      appIdentifier: undefined,
      listenPort: 8_081,
      targetOrigins: ["http://lab.example.test"],
      startTimeoutMs: 5_000,
    });
    if (!started.ok) throw started.error;
    const read = await lane.readInventory({
      sessionId: labVmSessionId,
      offset: 0,
      limit: 10,
    });
    if (!read.ok) throw read.error;
    const score = await scoreMitmLoop(read.value, fixture.flagSha256);
    expect(score).toMatchObject({
      kind: "flag_found",
      satisfied: true,
      recoveredFlagSha256: fixture.flagSha256,
      bodiesRead: 1,
    });
    expect(evidenceContainsValue(started.value, fixture.flag)).toBe(false);
    expect(evidenceContainsValue(read.value, fixture.flag)).toBe(false);
    expect(JSON.stringify(read.value)).not.toContain("flag{");
  });

  it("does not claim a flag the capture did not carry", async () => {
    const root = await createTestTempDirectory("rea-bench-loop-c-");
    const fixture = await createBenchLoopFixture(root);
    const lane = scriptedMitm({
      captureDirectory: fixture.captureDirectory,
      origin: "http://lab.example.test",
      pathTemplate: "/session/:id",
      bodiesHeld: 1,
    });
    const read = await lane.readInventory({
      sessionId: labVmSessionId,
      offset: 0,
      limit: 10,
    });
    if (!read.ok) throw read.error;
    const score = await scoreMitmLoop(read.value, "f".repeat(64));
    expect(score.satisfied).toBe(false);
    expect(score.recoveredFlagSha256).toBe(fixture.flagSha256);
  });
});

describe("Benchmark lane: flag metric through a scripted lab VM", () => {
  it("scores a fixture task as a flag found", async () => {
    const root = await createTestTempDirectory("rea-bench-task-");
    const fixture = await createBenchLoopFixture(root);
    const adapter = new BenchTaskAdapter({
      environment: { REA_BENCH_LIMA_PROFILE: "nyu-ctf-bench" },
      labVm: scriptedLabVm(fixture.taskWorkspace, {
        status: "completed",
        flag: fixture.flag,
      }),
    });
    const executed = await adapter.run({
      taskId: "nyu-ctf-bench/web-01",
      suite: "nyu-ctf-bench",
      workspacePath: fixture.taskWorkspace,
      entrypoint: "docker compose up harness",
      success: fixture.taskSuccess,
      budgetSeconds: 600,
    });
    if (!executed.ok) throw executed.error;
    const expectedDigest =
      fixture.taskSuccess.kind === "flag"
        ? fixture.taskSuccess.expected_flag_sha256
        : undefined;
    expect(executed.value.normalized_result).toMatchObject({
      task_id: "nyu-ctf-bench/web-01",
      status: "succeeded",
      metric: {
        kind: "flag",
        satisfied: true,
        reason: null,
        recovered_flag_sha256: expectedDigest,
      },
    });
    expect(evidenceContainsValue(executed.value, fixture.flag)).toBe(false);
  });
});
