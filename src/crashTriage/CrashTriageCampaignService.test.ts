import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { CRASH_MINIMIZE_LFZ_COMMAND_ENV } from "../domain/crashTriage/crashMinimization.js";
import { CRASH_REPORT_MAX_FRAME_CHARS } from "../domain/crashTriage/crashReport.js";
import {
  crashDedupListSchema,
  crashEvidenceSchema,
  fuzzingCampaignRegistrationSchema,
  fuzzingCampaignStatusResultSchema,
} from "../domain/crashTriage/fuzzingCampaign.js";
import type { Evidence } from "../domain/evidence.js";
import {
  CrashMinimizeConfigurationFailure,
  resolveCrashMinimizeConfiguration,
} from "./MinimizationConfiguration.js";
import { CrashTriageService } from "./CrashTriageService.js";

const services: CrashTriageService[] = [];

afterEach(async () => {
  await Promise.all(services.splice(0).map((service) => service.closeAll()));
});

const sha256 = (value: string): string =>
  createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");

interface Harness {
  readonly root: string;
  readonly storeRoot: string;
  readonly target: string;
  readonly seed: string;
  readonly repro: string;
  readonly service: CrashTriageService;
  readonly environment: Record<string, string>;
}

const harness = async (
  options: { readonly environment?: Record<string, string> } = {},
): Promise<Harness> => {
  const environment = options.environment ?? {};
  const root = await createTestTempDirectory("crash-triage-");
  const artifacts = join(root, "artifacts");
  const storeRoot = join(root, "store");
  await mkdir(artifacts, { recursive: true });
  const target = join(artifacts, "fuzz_target");
  const seed = join(artifacts, "seed");
  const repro = join(artifacts, "crash-input");
  await Promise.all([
    writeFile(target, "#!/bin/sh\nexit 0\n", { mode: 0o700 }),
    writeFile(seed, "AAAA", { mode: 0o600 }),
    writeFile(repro, "crash-bytes", { mode: 0o600 }),
  ]);
  let tick = 0;
  const service = new CrashTriageService({
    environment,
    createRuntimeRoot: async () => ({
      path: storeRoot,
      close: async () => {
        await rm(storeRoot, { recursive: true, force: true });
      },
    }),
    now: () => new Date(Date.UTC(2026, 9, 24, 10, 0, tick++)).toISOString(),
  });
  services.push(service);
  return {
    root,
    storeRoot,
    target,
    seed,
    repro,
    service,
    environment,
  };
};

const asanReport = (input: {
  readonly address: string;
  readonly source: string;
  readonly line: number;
  readonly functions: readonly string[];
  readonly kind?: string;
}): string =>
  [
    "=================================================================",
    `==1731==ERROR: AddressSanitizer: ${input.kind ?? "heap-buffer-overflow"} on address ${input.address} at pc 0x000105a2b3c0 bp 0x1 sp 0x2`,
    `WRITE of size 4 at ${input.address} thread T0`,
    ...input.functions.map(
      (name, index) =>
        `    #${String(index)} 0x${(0x105a2b3c0 + index).toString(16)} in ${name} ${input.source}:${String(
          input.line + index,
        )}:9`,
    ),
    "SUMMARY: AddressSanitizer: heap-buffer-overflow",
    "==1731==ABORTING",
    "",
  ].join("\n");

const resultOf = <T>(
  outcome: { readonly ok: true; readonly value: T } | { readonly ok: false },
): T => {
  if (!outcome.ok) throw new Error("Expected a successful result");
  return outcome.value;
};

const registered = (evidence: Evidence) =>
  fuzzingCampaignRegistrationSchema.parse(evidence.normalized_result);

const statusOf = (evidence: Evidence) =>
  fuzzingCampaignStatusResultSchema.parse(evidence.normalized_result);

const dedupsOf = (evidence: Evidence) =>
  crashDedupListSchema.parse(evidence.normalized_result);

const crashOf = (evidence: Evidence) =>
  crashEvidenceSchema.parse(evidence.normalized_result);

const register = async (harnessed: Harness) => {
  const evidence = resultOf(
    await harnessed.service.registerCampaign({
      targetPath: harnessed.target,
      seedPaths: [harnessed.seed],
      budget: { max_seconds: 600 },
      dedupFrames: 3,
    }),
  );
  return registered(evidence);
};

const record = async (harnessed: Harness, campaignId: string, body: string) =>
  resultOf(
    await harnessed.service.recordCrash({
      campaignId,
      reportBody: body,
      reproPath: harnessed.repro,
    }),
  );

describe("campaign registration", () => {
  it("digests the target and seeds and issues a server-lifetime identity", async () => {
    const harnessed = await harness();
    const evidence = resultOf(
      await harnessed.service.registerCampaign({
        targetPath: harnessed.target,
        seedPaths: [harnessed.seed],
        budget: { max_seconds: 600, max_crashes: 10 },
        dedupFrames: 3,
      }),
    );
    const registration = registered(evidence);
    expect(registration.campaign_id).toMatch(/^[0-9a-f-]{36}$/u);
    expect(registration.status).toBe("registered");
    expect(registration.target).toEqual({
      path: harnessed.target,
      sha256: sha256("#!/bin/sh\nexit 0\n"),
      bytes: 17,
    });
    expect(registration.seeds).toEqual([
      { path: harnessed.seed, sha256: sha256("AAAA"), bytes: 4 },
    ]);
    expect(registration.budget).toEqual({
      max_seconds: 600,
      max_crashes: 10,
    });
    expect(registration.dedup_frames).toBe(3);
    expect(registration.report_store_path).toBe(harnessed.storeRoot);
    expect(evidence.subject).toMatchObject({
      name: "fuzz_target",
      local_path: harnessed.target,
      format: "file",
      digest: { sha256: sha256("#!/bin/sh\nexit 0\n") },
    });
    expect(evidence.provider.id).toBe("rea-crash-triage");
    expect(evidence.predicate_type).toBe("fuzzing-campaign");
    expect(evidence.locations).toEqual(
      expect.arrayContaining([
        { kind: "artifact-path", path: harnessed.target },
        { kind: "artifact-path", path: harnessed.seed },
      ]),
    );
  });

  it("refuses a budget without a stop condition and writes nothing", async () => {
    const harnessed = await harness();
    const outcome = await harnessed.service.registerCampaign({
      targetPath: harnessed.target,
      seedPaths: [],
      budget: {},
      dedupFrames: 3,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisInputError);
    await expect(stat(harnessed.storeRoot)).rejects.toThrow();
  });

  it("refuses duplicate seeds and a corpus beyond the seed bound", async () => {
    const harnessed = await harness();
    const duplicate = await harnessed.service.registerCampaign({
      targetPath: harnessed.target,
      seedPaths: [harnessed.seed, harnessed.seed],
      budget: { max_runs: 100 },
      dedupFrames: 3,
    });
    expect(duplicate.ok).toBe(false);
    const tooMany = await harnessed.service.registerCampaign({
      targetPath: harnessed.target,
      seedPaths: Array.from({ length: 33 }, (_, index) =>
        join(harnessed.root, `seed-${String(index)}`),
      ),
      budget: { max_runs: 100 },
      dedupFrames: 3,
    });
    expect(tooMany.ok).toBe(false);
  });

  it("refuses a target that is not a regular file", async () => {
    const harnessed = await harness();
    const outcome = await harnessed.service.registerCampaign({
      targetPath: join(harnessed.root, "missing"),
      seedPaths: [],
      budget: { max_runs: 10 },
      dedupFrames: 3,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisInputError);
  });
});

describe("campaign reads", () => {
  it("reports an unknown campaign without creating the store", async () => {
    const harnessed = await harness();
    const outcome = await harnessed.service.campaignStatus({
      campaignId: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisInputError);
    await expect(stat(harnessed.storeRoot)).rejects.toThrow();
  });

  it("reports registered counters before any crash is recorded", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const status = statusOf(
      resultOf(
        await harnessed.service.campaignStatus({
          campaignId: registration.campaign_id,
        }),
      ),
    );
    expect(status).toMatchObject({
      campaign_id: registration.campaign_id,
      status: "registered",
      seed_count: 1,
      seed_bytes: 4,
      crash_count: 0,
      dedup_count: 0,
      last_crash_at: null,
    });
  });
});

describe("crash record evidence", () => {
  it("groups a stored report and exposes structural evidence", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const body = asanReport({
      address: "0x6020000000f1",
      source: "/home/fuzz/src/parser.c",
      line: 42,
      functions: [
        "parse_header",
        "load_file",
        "LLVMFuzzerTestOneInput",
        "main",
      ],
    });
    const summary = await record(harnessed, registration.campaign_id, body);
    expect(summary).toMatchObject({
      campaignId: registration.campaign_id,
      crashKind: "heap-buffer-overflow",
      sanitizerClass: "address",
      frameCount: 4,
      occurrenceCount: 1,
      dedupIsNew: true,
    });

    const status = statusOf(
      resultOf(
        await harnessed.service.campaignStatus({
          campaignId: registration.campaign_id,
        }),
      ),
    );
    expect(status.crash_count).toBe(1);
    expect(status.dedup_count).toBe(1);
    expect(status.last_crash_at).not.toBeNull();

    const listed = dedupsOf(
      resultOf(
        await harnessed.service.listDedups({
          campaignId: registration.campaign_id,
          limit: 50,
        }),
      ),
    );
    expect(listed.dedups).toHaveLength(1);
    expect(listed.dedups[0]).toMatchObject({
      dedup_id: summary.dedupId,
      crash_kind: "heap-buffer-overflow",
      sanitizer_class: "address",
      frame_count: 4,
      occurrence_count: 1,
      crash_ids: [summary.crashId],
    });
    expect(listed.dedups[0]?.top_frames).toEqual([
      "parse_header",
      "load_file",
      "LLVMFuzzerTestOneInput",
    ]);

    const evidence = resultOf(
      await harnessed.service.fetchCrashEvidence({
        campaignId: registration.campaign_id,
        crashId: summary.crashId,
      }),
    );
    const crash = crashOf(evidence);
    expect(crash).toMatchObject({
      crash_id: summary.crashId,
      dedup_id: summary.dedupId,
      crash_kind: "heap-buffer-overflow",
      sanitizer_class: "address",
      access: "write",
      occurrence_count: 1,
      summary: "SUMMARY: AddressSanitizer: heap-buffer-overflow",
    });
    expect(crash.frames.map((frame) => frame.function)).toEqual([
      "parse_header",
      "load_file",
      "LLVMFuzzerTestOneInput",
      "main",
    ]);
    expect(crash.crash_report.path).toBe(
      join(harnessed.storeRoot, "reports", `${summary.crashId}.txt`),
    );
    expect(crash.crash_report.sha256).toBe(sha256(body));
    expect(await readFile(crash.crash_report.path, "utf8")).toBe(body);
    const reportMode = (await stat(crash.crash_report.path)).mode & 0o777;
    expect(reportMode).toBe(0o600);
    expect(crash.repro_input).toEqual({
      path: harnessed.repro,
      bytes: 11,
      exists_now: true,
    });
    expect(evidence.locations).toEqual(
      expect.arrayContaining([
        { kind: "artifact-path", path: crash.crash_report.path },
        { kind: "artifact-path", path: harnessed.repro },
      ]),
    );

    await rm(harnessed.repro);
    const afterRemoval = crashOf(
      resultOf(
        await harnessed.service.fetchCrashEvidence({
          campaignId: registration.campaign_id,
          crashId: summary.crashId,
        }),
      ),
    );
    expect(afterRemoval.repro_input).toMatchObject({
      exists_now: false,
      bytes: 11,
    });
  });
});

describe("bounded inline crash text", () => {
  it("clips a hostile frame symbol instead of inlining report bytes", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const summary = await record(
      harnessed,
      registration.campaign_id,
      asanReport({
        address: "0x6020000000f1",
        source: "/src/parser.c",
        line: 42,
        functions: ["a".repeat(400_000), "main"],
      }),
    );
    const crash = crashOf(
      resultOf(
        await harnessed.service.fetchCrashEvidence({
          campaignId: registration.campaign_id,
          crashId: summary.crashId,
        }),
      ),
    );
    expect(crash.text_truncated).toBe(true);
    expect(crash.frames[0]?.text_truncated).toBe(true);
    expect(crash.frames[0]?.function).toHaveLength(
      CRASH_REPORT_MAX_FRAME_CHARS,
    );
    expect(crash.frames[0]?.function?.endsWith("…")).toBe(true);
    expect(crash.frames[1]?.function).toBe("main");
    expect(JSON.stringify(crash).length).toBeLessThan(20_000);
  });
});

describe("crash deduplication", () => {
  it("counts a repeated report as one crash and one group", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const body = asanReport({
      address: "0x6020000000f1",
      source: "/src/parser.c",
      line: 42,
      functions: ["parse_header", "load_file", "main"],
    });
    const first = await record(harnessed, registration.campaign_id, body);
    const second = await record(harnessed, registration.campaign_id, body);
    expect(second.crashId).toBe(first.crashId);
    expect(second.occurrenceCount).toBe(2);
    expect(second.dedupIsNew).toBe(false);
    const listed = dedupsOf(
      resultOf(
        await harnessed.service.listDedups({
          campaignId: registration.campaign_id,
          limit: 50,
        }),
      ),
    );
    expect(listed.dedup_count).toBe(1);
    expect(listed.dedups[0]).toMatchObject({
      occurrence_count: 2,
      crash_ids: [first.crashId],
    });
  });

  it("groups reports that differ only in addresses, paths, and lines", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const first = await record(
      harnessed,
      registration.campaign_id,
      asanReport({
        address: "0x6020000000f1",
        source: "/build/one/src/parser.c",
        line: 42,
        functions: ["parse_header", "load_file", "main"],
      }),
    );
    const second = await record(
      harnessed,
      registration.campaign_id,
      asanReport({
        address: "0x60c0000000f1",
        source: "/build/two/src/parser.c",
        line: 97,
        functions: ["parse_header", "load_file", "main"],
      }),
    );
    expect(second.crashId).not.toBe(first.crashId);
    expect(second.dedupId).toBe(first.dedupId);
    const listed = dedupsOf(
      resultOf(
        await harnessed.service.listDedups({
          campaignId: registration.campaign_id,
          limit: 50,
        }),
      ),
    );
    expect(listed.dedup_count).toBe(1);
    expect(listed.dedups[0]).toMatchObject({
      occurrence_count: 2,
      crash_ids: [first.crashId, second.crashId],
    });
  });

  it("keeps different crash kinds apart and bounds the listing", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    for (const kind of [
      "heap-buffer-overflow",
      "stack-buffer-overflow",
      "use-after-free",
    ])
      await record(
        harnessed,
        registration.campaign_id,
        asanReport({
          address: "0x6020000000f1",
          source: "/src/parser.c",
          line: 42,
          functions: ["parse_header", "main"],
          kind,
        }),
      );
    const all = dedupsOf(
      resultOf(
        await harnessed.service.listDedups({
          campaignId: registration.campaign_id,
          limit: 50,
        }),
      ),
    );
    expect(all.dedup_count).toBe(3);
    expect(all.truncated).toBe(false);
    const bounded = dedupsOf(
      resultOf(
        await harnessed.service.listDedups({
          campaignId: registration.campaign_id,
          limit: 1,
        }),
      ),
    );
    expect(bounded.dedups).toHaveLength(1);
    expect(bounded.dedup_count).toBe(3);
    expect(bounded.truncated).toBe(true);
  });
});

describe("crash record boundaries", () => {
  it("refuses an unrecognized report as an output error", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const outcome = await harnessed.service.recordCrash({
      campaignId: registration.campaign_id,
      reportBody: "this is not a crash report\n",
      reproPath: harnessed.repro,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisOutputError);
    expect(outcome.error).toMatchObject({
      userMessage: expect.stringMatching(/not a recognized/u),
    });
  });

  it("refuses a report above the parsing budget", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const outcome = await harnessed.service.recordCrash({
      campaignId: registration.campaign_id,
      reportBody: "x".repeat(4 * 1024 * 1024 + 1),
      reproPath: harnessed.repro,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisResourceConstraintError);
  });

  it("requires the reproducer input to exist", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const outcome = await harnessed.service.recordCrash({
      campaignId: registration.campaign_id,
      reportBody: asanReport({
        address: "0x6020000000f1",
        source: "/src/parser.c",
        line: 42,
        functions: ["parse_header"],
      }),
      reproPath: join(harnessed.root, "absent-input"),
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisInputError);
  });
});

describe("store lifetime", () => {
  it("removes the store and its retained reports on close", async () => {
    const harnessed = await harness();
    const registration = await register(harnessed);
    const summary = await record(
      harnessed,
      registration.campaign_id,
      asanReport({
        address: "0x6020000000f1",
        source: "/src/parser.c",
        line: 42,
        functions: ["parse_header"],
      }),
    );
    const reportPath = join(
      harnessed.storeRoot,
      "reports",
      `${summary.crashId}.txt`,
    );
    expect((await stat(reportPath)).isFile()).toBe(true);
    const closed = await harnessed.service.closeAll();
    expect(closed.ok).toBe(true);
    await expect(stat(harnessed.storeRoot)).rejects.toThrow();
    const afterClose = await harnessed.service.campaignStatus({
      campaignId: registration.campaign_id,
    });
    expect(afterClose.ok).toBe(false);
  });
});

const writeMinimizer = async (
  harnessed: Harness,
  body: string,
): Promise<string> => {
  const path = join(harnessed.root, "minimizer");
  await writeFile(path, `#!/bin/sh\n${body}`, { mode: 0o700 });
  await chmod(path, 0o700);
  return path;
};

describe("minimization hooks", () => {
  it("runs the caller-supplied libFuzzer target and reports the artifact", async () => {
    const harnessed = await harness();
    const command = await writeMinimizer(
      harnessed,
      [
        'out="$(printf "%s\\n" "$@" | sed -n "s/^-exact_artifact_path=//p")"',
        'printf "%s" "minimized" > "$out"',
        'printf "CRASH_MIN: 9 bytes\\nstat::number_of_executed_units: 120\\n"',
        "exit 0",
        "",
      ].join("\n"),
    );
    harnessed.environment[CRASH_MINIMIZE_LFZ_COMMAND_ENV] = command;
    const outputPath = join(harnessed.root, "minimized-crash");
    const outcome = await harnessed.service.minimizeCrash({
      engine: "libfuzzer",
      inputPath: harnessed.repro,
      outputPath,
      timeoutMs: 30_000,
      maxTotalSeconds: 60,
    });
    const observation = resultOf(outcome);
    expect(observation).toMatchObject({
      engine: "libfuzzer",
      exit_type: "exited",
      exit_code: 0,
      executions: 120,
      output_truncated: false,
      output_reported_bytes: 9,
    });
    expect(observation.input).toEqual({
      path: harnessed.repro,
      bytes: 11,
      sha256: sha256("crash-bytes"),
    });
    expect(observation.output).toEqual({
      path: outputPath,
      bytes: 9,
      sha256: sha256("minimized"),
    });
    expect(observation.byte_reduction).toBe(2);
  });

  it("refuses an unset minimizer and names the setting", async () => {
    const harnessed = await harness();
    const outcome = await harnessed.service.minimizeCrash({
      engine: "libfuzzer",
      inputPath: harnessed.repro,
      outputPath: join(harnessed.root, "out"),
      timeoutMs: 5_000,
      maxTotalSeconds: 5,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    expect(outcome.error).toMatchObject({
      remediationAction: expect.stringContaining(
        CRASH_MINIMIZE_LFZ_COMMAND_ENV,
      ),
      diagnostics: { setting: CRASH_MINIMIZE_LFZ_COMMAND_ENV },
    });
  });

  it("stops the minimizer at the caller's deadline", async () => {
    const harnessed = await harness();
    const command = await writeMinimizer(harnessed, "sleep 1\nexit 0\n");
    harnessed.environment[CRASH_MINIMIZE_LFZ_COMMAND_ENV] = command;
    const outcome = await harnessed.service.minimizeCrash({
      engine: "libfuzzer",
      inputPath: harnessed.repro,
      outputPath: join(harnessed.root, "out"),
      timeoutMs: 50,
      maxTotalSeconds: 5,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisTimeoutError);
  });

  it("refuses a search window outside the declared bound", async () => {
    const harnessed = await harness();
    const outcome = await harnessed.service.minimizeCrash({
      engine: "libfuzzer",
      inputPath: harnessed.repro,
      outputPath: join(harnessed.root, "out"),
      timeoutMs: 5_000,
      maxTotalSeconds: 1_000_000,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisInputError);
  });

  it("names an unreadable minimizer input as a crash input", async () => {
    const harnessed = await harness();
    const command = await writeMinimizer(harnessed, "exit 0\n");
    harnessed.environment[CRASH_MINIMIZE_LFZ_COMMAND_ENV] = command;
    const outcome = await harnessed.service.minimizeCrash({
      engine: "libfuzzer",
      inputPath: join(harnessed.root, "absent-input"),
      outputPath: join(harnessed.root, "out"),
      timeoutMs: 5_000,
      maxTotalSeconds: 5,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisInputError);
    expect(outcome.error).toMatchObject({
      userMessage: expect.stringContaining("crash input"),
    });
  });

  it("never overwrites an existing output path", async () => {
    const harnessed = await harness();
    const command = await writeMinimizer(harnessed, "exit 0\n");
    harnessed.environment[CRASH_MINIMIZE_LFZ_COMMAND_ENV] = command;
    const outputPath = join(harnessed.root, "existing-output");
    await writeFile(outputPath, "keep me");
    const outcome = await harnessed.service.minimizeCrash({
      engine: "libfuzzer",
      inputPath: harnessed.repro,
      outputPath,
      timeoutMs: 5_000,
      maxTotalSeconds: 5,
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toBeInstanceOf(AnalysisInputError);
    expect(await readFile(outputPath, "utf8")).toBe("keep me");
  });
});

describe("minimizer configuration", () => {
  it("fails closed on an unset, relative, or missing binary", async () => {
    const failures = [
      () => resolveCrashMinimizeConfiguration({}, "afl-tmin"),
      () =>
        resolveCrashMinimizeConfiguration(
          { REA_AFLTMIN_COMMAND: "bin/afl-tmin" },
          "afl-tmin",
        ),
      () =>
        resolveCrashMinimizeConfiguration(
          { REA_AFLTMIN_COMMAND: "/definitely/not/here/afl-tmin" },
          "afl-tmin",
        ),
    ].map((run) => {
      try {
        run();
        return null;
      } catch (cause: unknown) {
        return cause;
      }
    });
    expect(failures[0]).toBeInstanceOf(CrashMinimizeConfigurationFailure);
    expect(failures[1]).toMatchObject({ code: "not_absolute" });
    expect(failures[2]).toMatchObject({ code: "binary_missing" });
    expect(failures[0]).toMatchObject({
      code: "engine_not_configured",
      remediation: expect.stringContaining("REA_AFLTMIN_COMMAND"),
    });
  });

  it("refuses a file that is not executable", async () => {
    const harnessed = await harness();
    const path = join(harnessed.root, "not-executable");
    await writeFile(path, "#!/bin/sh\n", { mode: 0o600 });
    await chmod(path, 0o600);
    try {
      resolveCrashMinimizeConfiguration(
        { REA_AFLTMIN_COMMAND: path },
        "afl-tmin",
      );
      expect.unreachable();
    } catch (cause: unknown) {
      expect(cause).toMatchObject({ code: "binary_not_executable" });
    }
  });
});
