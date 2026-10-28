import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createCrashTriageService } from "../../../src/composition/crashTriage.js";
import { createFuzzingCampaignService } from "../../../src/composition/fuzzing.js";
import {
  crashDedupListSchema,
  fuzzingCampaignRegistrationSchema,
  fuzzingCampaignStatusResultSchema,
} from "../../../src/domain/crashTriage/fuzzingCampaign.js";
import { FUZZING_LFZ_COMMAND_ENV } from "../../../src/domain/fuzzing/fuzzingEngine.js";
import { fuzzingCampaignObservationSchema } from "../../../src/domain/fuzzing/fuzzingCampaignObservation.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const untrusted = { provenance: { untrusted_content: true } };

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

const connectClient = async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-fuzzing-mcp-"));
  const artifacts = join(directory, "artifacts");
  await mkdir(artifacts, { recursive: true });
  const engine = join(artifacts, "fuzz_target");
  await writeFile(
    engine,
    `#!/bin/sh\nexec "${process.execPath}" "${join(process.cwd(), "tests/fixtures/fuzzingFakeEngine.mjs")}" "$@"\n`,
    { mode: 0o700 },
  );
  await chmod(engine, 0o700);
  const seed = join(artifacts, "seed");
  await writeFile(seed, "AAAA", { mode: 0o600 });
  const crash = asanReport(["parse_items", "LLVMFuzzerTestOneInput"]);
  const scenario = join(directory, "scenario.json");
  await writeFile(
    scenario,
    JSON.stringify({
      engine: "libfuzzer",
      stats: [
        "#10\tpulse cov: 3 ft: 4 corp: 1/4b exec/s: 100 rss: 10Mb",
        "#120\tpulse cov: 12 ft: 8 corp: 3/12b exec/s: 150 rss: 10Mb",
      ],
      artifacts: [{ name: "crash-abc", content: "AAAA" }],
      reports: { "crash-abc": [crash, crash] },
      delayMs: 10,
      counterPath: join(directory, "counter"),
    }),
    "utf8",
  );
  const environment = {
    ...process.env,
    [FUZZING_LFZ_COMMAND_ENV]: engine,
    REA_FAKE_ENGINE_SCENARIO: scenario,
    REA_DISABLE_SANDBOX: "1",
  };
  const crashTriage = createCrashTriageService(environment);
  const fuzzing = createFuzzingCampaignService(environment, crashTriage);
  const session = createTestBinarySession(() => {
    throw new Error("Binary provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { crashTriage, fuzzing, environment },
  );
  const client = new Client({ name: "fuzzing", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    directory,
    client,
    async close() {
      await client.close();
      await server.close();
      await session.close();
      await rm(directory, { recursive: true, force: true });
    },
  };
};

const active = {
  client: undefined as Awaited<ReturnType<typeof connectClient>> | undefined,
};

beforeAll(async () => {
  active.client = await connectClient();
});

afterAll(async () => {
  await active.client?.close();
});

const call = async (
  client: NonNullable<typeof active.client>,
  name: string,
  arguments_: Record<string, unknown>,
) => {
  const result = await client.client.callTool({ name, arguments: arguments_ });
  expect(result.isError, name).not.toBe(true);
  return {
    result,
    value: (result.structuredContent as { normalized_result: unknown })
      .normalized_result,
  };
};

describe("fuzzing campaign MCP surface", () => {
  it("advertises the tool with valid schemas and its engine selections", async () => {
    const client = active.client!;
    const tools = (await client.client.listTools()).tools;
    const tool = tools.find(
      (candidate) => candidate.name === "start_fuzzing_campaign",
    );
    if (tool?.inputSchema === undefined || tool.outputSchema === undefined)
      throw new Error("Missing start_fuzzing_campaign schemas");
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    expect(ajv.validateSchema(tool.inputSchema)).toBe(true);
    expect(ajv.validateSchema(tool.outputSchema as AnySchema)).toBe(true);
    expect(tool.annotations).toMatchObject({
      readOnlyHint: false,
      idempotentHint: false,
    });
    expect(
      ajv.validate(tool.inputSchema as AnySchema, {
        campaign_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        engine: "libfuzzer",
      }),
    ).toBe(true);
    expect(
      ajv.validate(tool.inputSchema as AnySchema, {
        campaign_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        engine: "unsupported-engine",
      }),
    ).toBe(false);
  });

  it("registers a campaign, fuzzes it, and reports validated crashes", async () => {
    const client = active.client!;
    const registered = fuzzingCampaignRegistrationSchema.parse(
      (
        await call(client, "register_fuzzing_campaign", {
          target_path: join(active.client!.directory, "artifacts/fuzz_target"),
          seed_paths: [join(active.client!.directory, "artifacts/seed")],
          budget: { max_runs: 100 },
        })
      ).value,
    );
    const observed = await call(client, "start_fuzzing_campaign", {
      campaign_id: registered.campaign_id,
      engine: "libfuzzer",
      pov_repeats: 2,
    });
    expect(observed.result._meta).toMatchObject(untrusted);
    const observation = fuzzingCampaignObservationSchema.parse(observed.value);
    expect(observation.stop_reason).toBe("budget_runs");
    expect(observation.crashes.accepted).toBe(1);
    expect(observation.stats.last?.executions).toBe(120);

    const status = fuzzingCampaignStatusResultSchema.parse(
      (
        await call(client, "read_campaign_status", {
          campaign_id: registered.campaign_id,
        })
      ).value,
    );
    expect(status.crash_count).toBe(1);

    const dedups = crashDedupListSchema.parse(
      (
        await call(client, "list_crash_dedups", {
          campaign_id: registered.campaign_id,
          limit: 10,
        })
      ).value,
    );
    expect(dedups.dedups[0]?.crash_ids).toEqual([
      observation.crashes.ingested[0]?.crash_id,
    ]);
  });

  it("refuses a campaign nobody registered", async () => {
    const client = active.client!;
    const result = await client.client.callTool({
      name: "start_fuzzing_campaign",
      arguments: {
        campaign_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        engine: "libfuzzer",
      },
    });
    expect(result.isError).toBe(true);
  });
});
