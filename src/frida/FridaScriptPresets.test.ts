import { describe, expect, it } from "vitest";

import { FridaInstrumentationService } from "../application/frida/FridaInstrumentationService.js";
import type {
  FridaInstrumentationPort,
  FridaScriptObservation,
  FridaScriptSource,
} from "../application/frida/FridaInstrumentationPort.js";
import {
  FRIDA_SCRIPT_PRESETS,
  readFridaScriptPreset,
} from "./FridaScriptPresets.js";
import { FRIDA_SCRIPT_PRESET_NAMES } from "../domain/fridaScriptPreset.js";

const presetNames = new Set<string>();

describe("Frida script presets", () => {
  it("declares unique names that match the caller-visible enum", () => {
    for (const preset of FRIDA_SCRIPT_PRESETS) {
      expect(presetNames.has(preset.name)).toBe(false);
      presetNames.add(preset.name);
      expect(FRIDA_SCRIPT_PRESET_NAMES).toContain(preset.name);
    }
    expect([...presetNames].sort()).toEqual(
      [...FRIDA_SCRIPT_PRESET_NAMES].sort(),
    );
  });

  it("reads each preset's authored bytes with a digest of those bytes", async () => {
    for (const preset of FRIDA_SCRIPT_PRESETS) {
      const read = await readFridaScriptPreset(preset.name, "test");
      expect(read.ok, preset.name).toBe(true);
      if (!read.ok) continue;
      expect(read.value.sha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(read.value.bytes).toBe(
        Buffer.byteLength(read.value.source, "utf8"),
      );
      expect(read.value.source.length).toBeGreaterThan(0);
      expect(read.value.detectedMethods.length).toBeGreaterThan(0);
      expect(read.value.fileName).toBe(preset.fileName);
    }
  });

  it("refuses an unknown preset as an input error naming the vocabulary", async () => {
    const read = await readFridaScriptPreset(
      "does-not-exist" as (typeof FRIDA_SCRIPT_PRESET_NAMES)[number],
      "load_frida_script_preset",
    );
    expect(read.ok).toBe(false);
    if (read.ok) return;
    expect(read.error._tag).toBe("AnalysisInputError");
    expect(read.error.message).toContain("load_frida_script_preset");
  });

  it("keeps every preset's source free of upstream project text", async () => {
    for (const preset of FRIDA_SCRIPT_PRESETS) {
      const read = await readFridaScriptPreset(preset.name, "test");
      if (!read.ok) throw new Error("preset unreadable");
      expect(read.value.source).toContain("authored for this repository");
      expect(read.value.source).not.toMatch(/httptoolkit|copyright \(c\)/iu);
    }
  });
});

const fakePort = (
  loaded: FridaScriptObservation,
): {
  readonly port: FridaInstrumentationPort;
  readonly loads: { readonly source: FridaScriptSource }[];
} => {
  const loads: { readonly source: FridaScriptSource }[] = [];
  const unused = (): never => {
    throw new Error("this workflow does not use that provider method");
  };
  const port: FridaInstrumentationPort = {
    listDevices: unused,
    listProcesses: unused,
    startSession: unused,
    loadScript: async (_sessionId, source) => {
      loads.push({ source });
      return { ok: true, value: loaded };
    },
    resumeSession: unused,
    unloadScript: unused,
    rpcInventory: unused,
    callRpc: unused,
    status: () => undefined,
    closeSession: unused,
    closeAll: async () => undefined,
  };
  return { port, loads };
};

describe("load_frida_script_preset evidence", () => {
  it("loads the preset source and reports only its digest and declared methods", async () => {
    const { port, loads } = fakePort({
      scriptId: "00000000-0000-4000-8000-000000000002",
      sourceKind: "inline",
      sourcePath: null,
      sourceSha256: "0".repeat(64),
      messages: [],
      messagesTruncated: false,
    });
    const service = new FridaInstrumentationService(port);
    const result = await service.loadScriptPreset(
      "00000000-0000-4000-8000-000000000001",
      "ssl-unpinning",
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(loads).toHaveLength(1);
    expect(loads[0]!.source.sourceKind).toBe("inline");
    const preset = FRIDA_SCRIPT_PRESETS.find(
      ({ name }) => name === "ssl-unpinning",
    );
    const read = await readFridaScriptPreset("ssl-unpinning", "test");
    if (!read.ok || preset === undefined) throw new Error("fixture");
    expect(loads[0]!.source).toEqual({
      sourceKind: "inline",
      source: read.value.source,
    });
    expect(result.value.operation).toBe("load_frida_script_preset");
    expect(result.value.normalized_result).toMatchObject({
      preset: "ssl-unpinning",
      preset_title: preset.title,
      script_sha256: read.value.sha256,
      script_bytes: read.value.bytes,
      detected_methods: [...preset.detectedMethods],
      message_count: 0,
      messages_truncated: false,
    });
    const serialized = JSON.stringify(result.value);
    expect(serialized).not.toContain("Java.perform");
    expect(serialized).not.toContain(read.value.source.slice(0, 40));
    expect(result.value.parameters).toEqual({
      session_id: "00000000-0000-4000-8000-000000000001",
      preset: "ssl-unpinning",
    });
  });
});
