import { expect, test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { YaraProvider } from "../../../../src/yara/YaraProvider.js";
import { writeFakeYara, type FakeYaraBehavior } from "./fakeYara.js";

const providerFor = async (
  behavior: FakeYaraBehavior,
): Promise<{
  readonly provider: YaraProvider;
  readonly launcher: string;
  readonly callsPath: string;
  readonly root: string;
}> => {
  const root = await createTestTempDirectory("rea-yara-");
  const { launcher, callsPath } = await writeFakeYara(root, behavior);
  return {
    provider: new YaraProvider({
      environment: { REA_YARAX_COMMAND: launcher },
    }),
    launcher,
    callsPath,
    root,
  };
};

const matchesFixture = [
  {
    rule_id: "crypto_aes_sbox_head",
    namespace: "crypto/symmetric",
    tags: ["crypto"],
    meta: { description: "never reaches Evidence" },
    matches: [
      { identifier: "$sbox", offset: 4096, length: 16, data: "c2VjcmV0" },
    ],
  },
  {
    rule: "crypto_md5_initial_state",
    matches: [{ name: "$iv", offset: 16, length: 8 }],
  },
  { unexpected: true },
];

test("parses a YARA-X match array and never republishes matched bytes", async () => {
  const { provider, callsPath, root } = await providerFor({
    matches: matchesFixture,
  });
  const target = join(root, "sample.bin");
  const rules = join(root, "rules.yar");
  await writeFile(target, "TARGET-FIXTURE");
  await writeFile(rules, "rule a { condition: true }");
  const result = await provider.execute({
    operation: "scan_artifact_with_rules",
    input: { path: target, rules_path: rules },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.client).toEqual({
    command: expect.any(String),
    version: "0.15.0",
  });
  expect(value.sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(value.rules_sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(value.rule_pack).toBeNull();
  expect(value.match_count).toBe(2);
  expect(value.field_match_count).toBe(2);
  expect(value.unparsed_entries).toBe(1);
  expect(value.coverage).toBe("partial");
  expect(value.matches).toEqual([
    {
      rule_id: "crypto_aes_sbox_head",
      namespace: "crypto/symmetric",
      tags: ["crypto"],
      fields: [{ identifier: "$sbox", offset: 4096, length: 16 }],
    },
    {
      rule_id: "crypto_md5_initial_state",
      namespace: null,
      tags: [],
      fields: [{ identifier: "$iv", offset: 16, length: 8 }],
    },
  ]);
  // Matched bytes and rule metadata are absent from the serialized Evidence.
  expect(JSON.stringify(result.value)).not.toContain("c2VjcmV0");
  expect(JSON.stringify(result.value)).not.toContain("never reaches Evidence");
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain(
    `["scan","--output-format=json","${rules}","${target}"]`,
  );
});

test("scans with REA's verified crypto-constant pack", async () => {
  const { provider, root } = await providerFor({
    matches: [matchesFixture[0]],
  });
  const target = join(root, "firmware.bin");
  await writeFile(target, "BLOB");
  const result = await provider.execute({
    operation: "scan_for_crypto_constants",
    input: { path: target },
  });
  expect(
    result.ok,
    result.ok ? "" : `${result.error._tag}: ${result.error.message}`,
  ).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.rule_pack).toBe("rea-crypto-constants");
  expect(value.rule_pack_version).toBe(1);
  expect(value.rules_path).toContain("third_party/yara-rules/crypto");
  expect(value.rules_sha256).toBe(
    "df4b2b6059e7537203f343689e6d5073250744e998a67ae8a3e2e76c93822fb7",
  );
  expect(value.coverage).toBe("complete");
  await provider.close();
});

test("refuses plainly when no YARA-X binary is selected", async () => {
  const provider = new YaraProvider({ environment: {} });
  const result = await provider.execute({
    operation: "scan_for_crypto_constants",
    input: { path: "/does/not/matter.bin" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_YARAX_COMMAND");
  await provider.close();
});

test("rejects output that is not a match array without partial success", async () => {
  const { provider, root } = await providerFor({ matches: { rows: [] } });
  const target = join(root, "sample.bin");
  const rules = join(root, "rules.yar");
  await writeFile(target, "TARGET-FIXTURE");
  await writeFile(rules, "rule a { condition: true }");
  const result = await provider.execute({
    operation: "scan_artifact_with_rules",
    input: { path: target, rules_path: rules },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("caps the published rule inventory and marks it partial", async () => {
  const { provider, root } = await providerFor({ matches: matchesFixture });
  const target = join(root, "sample.bin");
  const rules = join(root, "rules.yar");
  await writeFile(target, "TARGET-FIXTURE");
  await writeFile(rules, "rule a { condition: true }");
  const result = await provider.execute({
    operation: "scan_artifact_with_rules",
    input: { path: target, rules_path: rules, max_matches: 1 },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.match_count).toBe(1);
  expect(value.truncated).toBe(true);
  expect(value.coverage).toBe("partial");
  await provider.close();
});

test("reports the YARA-X client as available only after a version probe", async () => {
  const { provider } = await providerFor({});
  const available = await provider.inspectAvailability();
  expect(available.status).toBe("available");
  expect(available.diagnostics).toMatchObject({ version: "0.15.0" });
  await provider.close();

  const unconfigured = new YaraProvider({ environment: {} });
  const unavailable = await unconfigured.inspectAvailability();
  expect(unavailable).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await unconfigured.close();
});

test("rejects a missing target without starting YARA-X", async () => {
  const { provider, callsPath, root } = await providerFor({});
  const rules = join(root, "rules.yar");
  await writeFile(rules, "rule a { condition: true }");
  const result = await provider.execute({
    operation: "scan_artifact_with_rules",
    input: { path: join(root, "absent.bin"), rules_path: rules },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  await provider.close();
  expect(await readFile(callsPath, "utf8")).not.toContain('"scan"');
});
