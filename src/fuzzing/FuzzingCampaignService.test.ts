import { chmod, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import { LabVmSessionManager } from "../vmlab/LabVmSessionManager.js";
import { CrashTriageService } from "../crashTriage/CrashTriageService.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import {
  crashDedupListSchema,
  fuzzingCampaignRegistrationSchema,
  fuzzingCampaignStatusResultSchema,
} from "../domain/crashTriage/fuzzingCampaign.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { FUZZING_LFZ_COMMAND_ENV } from "../domain/fuzzing/fuzzingEngine.js";
import { fuzzingCampaignObservationSchema } from "../domain/fuzzing/fuzzingCampaignObservation.js";
import type { SandboxLaunchRequest } from "../domain/sandboxProfiles.js";
import { LAB_VM_PROVIDER } from "../domain/vmlab/labVm.js";
import { FuzzingCampaignService } from "./FuzzingCampaignService.js";

const services: {
  readonly fuzzing: FuzzingCampaignService;
  readonly triage: CrashTriageService;
}[] = [];

afterEach(async () => {
  for (const service of services.splice(0)) {
    await service.fuzzing.closeAll();
    await service.triage.closeAll();
  }
});

const asanReport = (functions: readonly string[]): string =>
  [
    "=================================================================",
    "==1731==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x000105a2b3c0 at pc 0x000105a2b3c4 bp 0x1 sp 0x2",
    "WRITE of size 4 at 0x000105a2b3c0 thread T0",
    ...functions.map(
      (name, index) =>
        `    #${String(index)} 0x${(0x105a2b3c0 + index).toString(16)} in ${name} /src/target.c:${String(12 + index)}:9`,
    ),
    "SUMMARY: AddressSanitizer: heap-buffer-overflow",
    "==1731==ABORTING",
    "",
  ].join("\n");

interface Harness {
  readonly root: string;
  readonly engine: string;
  readonly target: string;
  readonly seed: string;
  readonly scenario: string;
  readonly triage: CrashTriageService;
  readonly fuzzing: FuzzingCampaignService;
  readonly environment: Record<string, string>;
}

interface Scenario {
  readonly stats?: readonly string[];
  readonly artifacts?: readonly { name: string; content?: string }[];
  readonly reports?: Readonly<Record<string, readonly string[]>>;
  readonly counterPath?: string;
  readonly delayMs?: number;
  readonly holdMs?: number;
  readonly exitCode?: number;
  readonly engine?: string;
  readonly statsFile?: Readonly<Record<string, number>>;
  readonly reproduceCrashes?: number;
}

/** Lima stand-in: writes the guest files the run would have produced. */
const fakeLabVmPort = (workspacePath: string, report: string): LabVmPort => {
  const hostOf = (guest: string): string =>
    join(workspacePath, ...guest.split("/workspace/")[1]!.split("/"));
  return {
    defaultCommandTimeoutMs: 120_000,
    inspectAvailability: () => ({
      status: "available",
      code: null,
      reason: null,
      diagnostics: {},
    }),
    start: async () => {
      throw new Error("no start");
    },
    stop: async () => {
      throw new Error("no stop");
    },
    closeAll: async () => ({ ok: true, value: null }),
    run: async (request) => {
      const directory = /cd '([^']+)'/u.exec(request.command)?.[1];
      if (directory === undefined) throw new Error("no directory");
      const hostDirectory = hostOf(directory);
      await mkdir(join(hostDirectory, "artifacts"), { recursive: true });
      if (request.command.includes("report.log"))
        await writeFile(join(hostDirectory, "report.log"), report, "utf8");
      else {
        await writeFile(
          join(hostDirectory, "engine.log"),
          "#1\tpulse cov: 4 ft: 2 corp: 1/4b exec/s: 12 rss: 9Mb\n#9\tpulse cov: 7 ft: 3 corp: 2/8b exec/s: 20 rss: 9Mb\n",
          "utf8",
        );
        await writeFile(join(hostDirectory, "artifacts", "crash-lab"), "EEEE", {
          mode: 0o600,
        });
      }
      return {
        ok: true,
        value: createEvidence(undefined, LAB_VM_PROVIDER, {
          operation: "run_lab_vm_command",
          parameters: { session_id: request.sessionId },
          result: {
            session_id: request.sessionId,
            command: request.command,
            exit_type: "exited",
            exit_code: 0,
            duration_ms: 12,
            timeout_ms: request.timeoutMs,
            stdout_bytes: 0,
            stderr_bytes: 0,
            output_truncated: false,
            produced_paths: [],
            modified_paths: [],
            removed_paths: [],
            changes_truncated: false,
          },
          confidence: "observed",
          authority: "controlled-replay",
        }),
      };
    },
  };
};

const fixture = join(process.cwd(), "tests/fixtures/fuzzingFakeEngine.mjs");

const writeEngine = async (path: string): Promise<void> => {
  await writeFile(
    path,
    `#!/bin/sh\nexec "${process.execPath}" "${fixture}" "$@"\n`,
    { mode: 0o700 },
  );
  await chmod(path, 0o700);
};

const harness = async (scenario: Scenario): Promise<Harness> => {
  const root = await createTestTempDirectory("fuzzing-campaign-");
  const workspace = join(root, "artifacts");
  await mkdir(workspace, { recursive: true });
  const engine = join(workspace, "fuzz_target");
  const target = engine;
  const seed = join(workspace, "seed");
  await writeEngine(engine);
  await writeFile(seed, "AAAA", { mode: 0o600 });
  const scenarioPath = join(root, "scenario.json");
  await writeFile(
    scenarioPath,
    JSON.stringify({
      counterPath: join(root, "counter"),
      ...scenario,
    }),
    "utf8",
  );
  const storeRoot = join(root, "store");
  const triage = new CrashTriageService({
    environment: {},
    createRuntimeRoot: async () => ({
      path: storeRoot,
      close: async () => {
        await rm(storeRoot, { recursive: true, force: true });
      },
    }),
  });
  let campaignRoots = 0;
  const fuzzing = new FuzzingCampaignService({
    crashTriage: triage,
    environment: {
      ...process.env,
      [FUZZING_LFZ_COMMAND_ENV]: engine,
      REA_FAKE_ENGINE_SCENARIO: scenarioPath,
      REA_DISABLE_SANDBOX: "1",
    },
    statsIntervalMs: 5,
    createRuntimeRoot: async () => {
      const path = join(root, `campaign-${String(campaignRoots++)}`);
      await mkdir(path, { recursive: true, mode: 0o700 });
      return {
        path,
        close: async () => {
          await rm(path, { recursive: true, force: true });
        },
      };
    },
  });
  services.push({ fuzzing, triage });
  return {
    root,
    engine,
    target,
    seed,
    scenario: scenarioPath,
    triage,
    fuzzing,
    environment: { REA_DISABLE_SANDBOX: "1" },
  };
};

const resultOf = <T>(
  outcome: { readonly ok: true; readonly value: T } | { readonly ok: false },
): T => {
  if (!outcome.ok) throw new Error("Expected a successful result");
  return outcome.value;
};

const register = async (
  harnessed: Harness,
  budget: { max_runs?: number; max_seconds?: number; max_crashes?: number },
): Promise<string> => {
  const evidence = resultOf(
    await harnessed.triage.registerCampaign({
      targetPath: harnessed.target,
      seedPaths: [harnessed.seed],
      budget,
      dedupFrames: 3,
    }),
  );
  return fuzzingCampaignRegistrationSchema.parse(evidence.normalized_result)
    .campaign_id;
};

const observationOf = (evidence: Evidence) =>
  fuzzingCampaignObservationSchema.parse(evidence.normalized_result);

const statusOf = (evidence: Evidence) =>
  fuzzingCampaignStatusResultSchema.parse(evidence.normalized_result);

const dedupsOf = (evidence: Evidence) =>
  crashDedupListSchema.parse(evidence.normalized_result);

describe("fuzzing campaign service", () => {
  it("runs libFuzzer, enforces the run budget, and ingests a validated crash", async () => {
    const crash = asanReport(["parse_items", "LLVMFuzzerTestOneInput"]);
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: [
        "#10\tpulse  cov: 3 ft: 4 corp: 1/4b lim: 6 exec/s: 100 rss: 10Mb",
        "#40\tNEW    cov: 9 ft: 6 corp: 2/8b exec/s: 120 rss: 10Mb",
        "#120\tpulse cov: 12 ft: 8 corp: 3/12b exec/s: 150 rss: 10Mb",
      ],
      artifacts: [{ name: "crash-abc", content: "AAAA" }],
      reports: { "crash-abc": [crash, crash] },
      delayMs: 20,
    });
    const campaignId = await register(harnessed, { max_runs: 100 });
    const evidence = resultOf(
      await harnessed.fuzzing.startCampaign({
        campaignId,
        engine: "libfuzzer",
        povRepeats: 2,
        expectedSanitizer: undefined,
        minimizeCrashes: false,
        labVm: null,
      }),
    );
    const observation = observationOf(evidence);
    expect(observation.engine).toBe("libfuzzer");
    expect(observation.route).toBe("host");
    expect(observation.stop_reason).toBe("budget_runs");
    expect(observation.crashes).toMatchObject({
      observed: 1,
      inspected: 1,
      accepted: 1,
      rejected: 0,
    });
    const ingested = observation.crashes.ingested[0]!;
    expect(ingested.crash_id).toMatch(/^crash_/u);
    expect(ingested.dedup_id).toMatch(/^dedup_/u);
    expect(ingested.sanitizer_class).toBe("address");
    expect(observation.stats.last?.executions).toBe(120);
    expect(observation.stats.peak_executions_per_second).toBe(150);
    expect(observation.sandbox.limitations.join(" ")).toContain(
      "REA_DISABLE_SANDBOX",
    );
    expect(await stat(ingested.input_path)).toMatchObject({ size: 4 });

    const status = statusOf(
      resultOf(await harnessed.triage.campaignStatus({ campaignId })),
    );
    expect(status.crash_count).toBe(1);
    expect(status.dedup_count).toBe(1);
    const dedups = dedupsOf(
      resultOf(await harnessed.triage.listDedups({ campaignId, limit: 10 })),
    );
    expect(dedups.dedups).toHaveLength(1);
    expect(dedups.dedups[0]?.crash_ids).toEqual([ingested.crash_id]);
  });
});

describe("POV validation through the campaign service", () => {
  it("refuses an unreadable report and an unexpected sanitizer class", async () => {
    const crash = asanReport(["parse_items"]);
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#5\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 9 rss: 9Mb"],
      artifacts: [
        { name: "crash-bad", content: "BBBB" },
        { name: "crash-good", content: "CCCC" },
      ],
      reports: {
        "crash-bad": ["not a crash report"],
        "crash-good": [crash, crash],
      },
    });
    const campaignId = await register(harnessed, { max_seconds: 30 });
    const observation = observationOf(
      resultOf(
        await harnessed.fuzzing.startCampaign({
          campaignId,
          engine: "libfuzzer",
          povRepeats: 2,
          expectedSanitizer: "thread",
          minimizeCrashes: false,
          labVm: null,
        }),
      ),
    );
    expect(observation.crashes.accepted).toBe(0);
    expect(observation.crashes.rejected).toBe(2);
    expect(
      observation.crashes.rejected_rows.map((row) => row.reason).sort(),
    ).toEqual(["report_unreadable", "unsupported_sanitizer"]);
  });

  it("refuses a candidate whose reproductions disagree", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#5\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 9 rss: 9Mb"],
      artifacts: [{ name: "crash-flaky", content: "DDDD" }],
      reports: {
        "crash-flaky": [
          asanReport(["parse_items"]),
          asanReport(["consume_items"]),
        ],
      },
    });
    const campaignId = await register(harnessed, { max_seconds: 30 });
    const observation = observationOf(
      resultOf(
        await harnessed.fuzzing.startCampaign({
          campaignId,
          engine: "libfuzzer",
          povRepeats: 2,
          expectedSanitizer: undefined,
          minimizeCrashes: false,
          labVm: null,
        }),
      ),
    );
    expect(observation.crashes.accepted).toBe(0);
    expect(observation.crashes.rejected_rows[0]?.reason).toBe("unstable_state");
  });
  it("refuses a candidate that crashes in fewer reproductions than requested", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#5\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 9 rss: 9Mb"],
      artifacts: [{ name: "crash-once", content: "FFFF" }],
      reports: { "crash-once": [asanReport(["parse_items"])] },
      reproduceCrashes: 1,
    });
    const campaignId = await register(harnessed, { max_seconds: 30 });
    const observation = observationOf(
      resultOf(
        await harnessed.fuzzing.startCampaign({
          campaignId,
          engine: "libfuzzer",
          povRepeats: 2,
          expectedSanitizer: undefined,
          minimizeCrashes: false,
          labVm: null,
        }),
      ),
    );
    expect(observation.crashes.accepted).toBe(0);
    expect(observation.crashes.rejected_rows[0]?.reason).toBe("not_reproduced");
  });
});

describe("launch sandbox and campaign concurrency", () => {
  it("wraps every reproduction launch in the sandbox profile", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#5\tpulse cov: 1 ft: 1 corp: 1/4b exec: 9 rss: 9Mb"],
      artifacts: [{ name: "crash-wrapped", content: "GGGG" }],
      reports: {
        "crash-wrapped": [
          asanReport(["parse_items"]),
          asanReport(["parse_items"]),
        ],
      },
    });
    const campaignId = await register(harnessed, { max_seconds: 30 });
    const requests: SandboxLaunchRequest[] = [];
    const fuzzing = new FuzzingCampaignService({
      crashTriage: harnessed.triage,
      environment: {
        ...process.env,
        [FUZZING_LFZ_COMMAND_ENV]: harnessed.engine,
        REA_FAKE_ENGINE_SCENARIO: harnessed.scenario,
      },
      statsIntervalMs: 5,
      sandboxLaunch: (request) => {
        requests.push(request);
        return {
          executable: request.executable,
          args: [...request.args],
          limitations: [],
        };
      },
      createRuntimeRoot: async () => {
        const path = join(harnessed.root, "wrapped");
        await mkdir(path, { recursive: true, mode: 0o700 });
        return {
          path,
          close: async () => {
            await rm(path, { recursive: true, force: true });
          },
        };
      },
    });
    services.push({ fuzzing, triage: harnessed.triage });
    const observation = observationOf(
      resultOf(
        await fuzzing.startCampaign({
          campaignId,
          engine: "libfuzzer",
          povRepeats: 2,
          expectedSanitizer: undefined,
          minimizeCrashes: false,
          labVm: null,
        }),
      ),
    );
    expect(observation.crashes.accepted).toBe(1);
    expect(requests).toHaveLength(3);
    const [engineLaunch, ...reproductions] = requests;
    expect(engineLaunch?.args.join(" ")).toContain("-artifact_prefix=");
    expect(engineLaunch?.profile.workspace_root).toBe(
      observation.workspace.root,
    );
    expect(engineLaunch?.profile.executable_paths).toEqual([
      harnessed.engine,
      harnessed.target,
    ]);
    for (const reproduction of reproductions) {
      expect(reproduction.executable).toBe(harnessed.engine);
      expect(reproduction.profile.workspace_root).toBe(
        observation.workspace.root,
      );
      expect(reproduction.profile.executable_paths).toEqual([harnessed.engine]);
      expect(reproduction.profile.readable_paths).toContain(
        observation.workspace.root,
      );
      expect(
        reproduction.profile.writable_paths?.some((path) =>
          path.startsWith(observation.workspace.root),
        ),
      ).toBe(true);
    }
  });

  it("refuses a second campaign while one is running", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#5\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 9 rss: 9Mb"],
      holdMs: 10_000,
    });
    const campaignId = await register(harnessed, { max_seconds: 1 });
    const request = {
      campaignId,
      engine: "libfuzzer" as const,
      povRepeats: 1,
      expectedSanitizer: undefined,
      minimizeCrashes: false,
      labVm: null,
    };
    const first = harnessed.fuzzing.startCampaign(request);
    const second = await harnessed.fuzzing.startCampaign(request);
    expect(second.ok).toBe(false);
    if (second.ok) throw new Error("Expected a resource refusal");
    expect(second.error).toBeInstanceOf(AnalysisResourceConstraintError);
    expect(observationOf(resultOf(await first)).stop_reason).toBe(
      "budget_seconds",
    );
  }, 20_000);
});

describe("campaign budgets, cancellation, and lifecycle", () => {
  it("stops at the runtime cap and reports which seconds bound applied", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#5\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 9 rss: 9Mb"],
      holdMs: 5_000,
    });
    const campaignId = await register(harnessed, { max_seconds: 600 });
    const settings = () => ({
      revision: 1,
      overrides: { "fuzzing.max_campaign_seconds": 1 },
    });
    const fuzzing = new FuzzingCampaignService({
      crashTriage: harnessed.triage,
      environment: {
        ...process.env,
        [FUZZING_LFZ_COMMAND_ENV]: harnessed.engine,
        REA_FAKE_ENGINE_SCENARIO: harnessed.scenario,
        REA_DISABLE_SANDBOX: "1",
      },
      settings,
      statsIntervalMs: 5,
      createRuntimeRoot: async () => {
        const path = join(harnessed.root, "capped");
        await mkdir(path, { recursive: true, mode: 0o700 });
        return {
          path,
          close: async () => {
            await rm(path, { recursive: true, force: true });
          },
        };
      },
    });
    services.push({ fuzzing, triage: harnessed.triage });
    const observation = observationOf(
      resultOf(
        await fuzzing.startCampaign({
          campaignId,
          engine: "libfuzzer",
          povRepeats: 1,
          expectedSanitizer: undefined,
          minimizeCrashes: false,
          labVm: null,
        }),
      ),
    );
    expect(observation.budget.seconds_bound).toBe("runtime_cap");
    expect(observation.budget.effective.max_seconds).toBe(1);
    expect(observation.budget.runtime_cap_seconds).toBe(1);
    expect(observation.stop_reason).toBe("runtime_cap_seconds");
    expect(observation.status).toBe("stopped");
  }, 20_000);

  it("reports caller cancellation as a stopped campaign", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#5\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 9 rss: 9Mb"],
      holdMs: 10_000,
    });
    const campaignId = await register(harnessed, { max_seconds: 60 });
    const controller = new AbortController();
    const running = harnessed.fuzzing.startCampaign(
      {
        campaignId,
        engine: "libfuzzer",
        povRepeats: 1,
        expectedSanitizer: undefined,
        minimizeCrashes: false,
        labVm: null,
      },
      { signal: controller.signal },
    );
    setTimeout(() => controller.abort(), 80);
    const observation = observationOf(resultOf(await running));
    expect(observation.stop_reason).toBe("cancelled");
    expect(observation.status).toBe("stopped");
  }, 20_000);

  it("fails closed when no engine is configured", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#1\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 1 rss: 9Mb"],
    });
    const campaignId = await register(harnessed, { max_seconds: 10 });
    const fuzzing = new FuzzingCampaignService({
      crashTriage: harnessed.triage,
      environment: {},
    });
    services.push({ fuzzing, triage: harnessed.triage });
    const failed = await fuzzing.startCampaign({
      campaignId,
      engine: "libfuzzer",
      povRepeats: 1,
      expectedSanitizer: undefined,
      minimizeCrashes: false,
      labVm: null,
    });
    expect(failed.ok).toBe(false);
    if (failed.ok) throw new Error("Expected a refusal");
    expect(failed.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    expect(
      (failed.error as AnalysisCapabilityUnavailableError).remediationAction,
    ).toContain(FUZZING_LFZ_COMMAND_ENV);
  });

  it("removes retained campaign roots when the server closes", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#1\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 1 rss: 9Mb"],
    });
    const campaignId = await register(harnessed, { max_seconds: 10 });
    const observation = observationOf(
      resultOf(
        await harnessed.fuzzing.startCampaign({
          campaignId,
          engine: "libfuzzer",
          povRepeats: 1,
          expectedSanitizer: undefined,
          minimizeCrashes: false,
          labVm: null,
        }),
      ),
    );
    expect((await stat(observation.workspace.root)).isDirectory()).toBe(true);
    expect(await harnessed.fuzzing.closeAll()).toMatchObject({ ok: true });
    await expect(stat(observation.workspace.root)).rejects.toThrow();
  });
});

describe("lab-VM route", () => {
  it("runs the engine inside a lab VM through the shared workspace", async () => {
    const root = await createTestTempDirectory("fuzzing-labvm-");
    const workspacePath = join(root, "vm-workspace");
    await mkdir(workspacePath, { recursive: true });
    const target = join(workspacePath, "fuzz_target");
    await writeEngine(target);
    const seed = join(workspacePath, "seed");
    await writeFile(seed, "SEED", { mode: 0o600 });
    const crash = asanReport(["parse_items"]);
    const storeRoot = join(root, "store");
    const triage = new CrashTriageService({
      environment: {},
      createRuntimeRoot: async () => ({
        path: storeRoot,
        close: async () => {
          await rm(storeRoot, { recursive: true, force: true });
        },
      }),
    });
    const labVm = fakeLabVmPort(workspacePath, crash);
    const fuzzing = new FuzzingCampaignService({
      crashTriage: triage,
      labVm,
      environment: {
        ...process.env,
        [FUZZING_LFZ_COMMAND_ENV]: "/usr/local/bin/fuzz_target",
        REA_DISABLE_SANDBOX: "1",
      },
      statsIntervalMs: 5,
    });
    services.push({ fuzzing, triage });
    const campaignId = fuzzingCampaignRegistrationSchema.parse(
      resultOf(
        await triage.registerCampaign({
          targetPath: target,
          seedPaths: [seed],
          budget: { max_seconds: 30 },
          dedupFrames: 3,
        }),
      ).normalized_result,
    ).campaign_id;
    const observation = observationOf(
      resultOf(
        await fuzzing.startCampaign({
          campaignId,
          engine: "libfuzzer",
          povRepeats: 2,
          expectedSanitizer: undefined,
          minimizeCrashes: false,
          labVm: {
            sessionId: "2f1c9d4e-0b6a-4c8f-9e37-5a1f0d2b7c33",
            workspacePath,
          },
        }),
      ),
    );
    expect(observation.route).toBe("lab_vm");
    expect(observation.lab_vm).toMatchObject({
      exit_type: "exited",
      workspace_path: workspacePath,
    });
    expect(observation.sandbox.confined).toBe(false);
    expect(observation.stats.last?.executions).toBe(9);
    expect(observation.crashes.accepted).toBe(1);
    expect(observation.workspace.root).toBe(
      join(workspacePath, "rea-fuzzing", campaignId),
    );
  }, 20_000);

  it("refuses a lab-VM target outside the mounted workspace", async () => {
    const harnessed = await harness({
      engine: "libfuzzer",
      stats: ["#1\tpulse cov: 1 ft: 1 corp: 1/4b exec/s: 1 rss: 9Mb"],
    });
    const campaignId = await register(harnessed, { max_seconds: 10 });
    const labVm = new LabVmSessionManager({ environment: {} });
    const fuzzing = new FuzzingCampaignService({
      crashTriage: harnessed.triage,
      labVm,
      environment: {
        ...process.env,
        [FUZZING_LFZ_COMMAND_ENV]: "/usr/local/bin/fuzz_target",
      },
      statsIntervalMs: 5,
    });
    services.push({ fuzzing, triage: harnessed.triage });
    const refused = await fuzzing.startCampaign({
      campaignId,
      engine: "libfuzzer",
      povRepeats: 1,
      expectedSanitizer: undefined,
      minimizeCrashes: false,
      labVm: {
        sessionId: "2f1c9d4e-0b6a-4c8f-9e37-5a1f0d2b7c33",
        workspacePath: join(harnessed.root, "unmounted-vm"),
      },
    });
    expect(refused.ok).toBe(false);
    if (refused.ok) throw new Error("Expected a refusal");
    expect(refused.error).toBeInstanceOf(AnalysisInputError);
  });
});
