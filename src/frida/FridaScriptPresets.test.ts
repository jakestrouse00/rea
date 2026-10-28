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

/**
 * The Objective-C section of one preset: its `hookObjC` function through the
 * end of the file. Java halves stay above it, so a Java `implementation`
 * assignment cannot be mistaken for an Objective-C one.
 */
const objcRegion = (source: string): string | null => {
  const start = source.indexOf("function hookObjC() {");
  return start === -1 ? null : source.slice(start);
};

/**
 * The documented hook shape each preset with an Objective-C section must use.
 * A new ObjC preset has to add its shape here, so an unreviewed hook idiom
 * cannot ship silently.
 */
const OBJC_HOOK_SHAPES: Readonly<Record<string, RegExp>> = {
  "jail-root-detect-bypass":
    /method\.implementation = ObjC\.implement\(\s*method\s*,\s*function\s*\(\s*self\s*,\s*sel\b/u,
  "ssl-unpinning": /Interceptor\.attach\(\s*evaluate\s*,\s*\{/u,
};

/**
 * How a preset that replaces an Objective-C method reads its `id` argument.
 * `ObjC.implement` passes every `'@'` parameter as the raw pointer (it builds a
 * bare NativeCallback; object wrapping belongs to `ObjC.registerClass`'s method
 * wrappers), so a callback that compares `String(path)` never matches and the
 * hook can only pass through. A method replacement must therefore name its
 * conversion here.
 */
const OBJC_ID_CONVERSION: Readonly<Record<string, RegExp>> = {
  "jail-root-detect-bypass": /new ObjC\.Object\(\s*path\s*\)/u,
};

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

  it("hooks Objective-C methods the way the vendored bridge accepts them", async () => {
    // No Frida runtime exists in this workspace, so the shipped agents are
    // checked structurally against the frida-objc-bridge contract: an
    // implementation slot holds a NativePointer (the bridge's setter compares
    // `imp.equals(oldImp)`), so a plain JS function is rejected at assignment.
    // `ObjC.implement(method, fn)` is the documented way to build that
    // pointer; `ObjC.implement(Class, selector, fn)` and the nonexistent
    // `ObjC.intercept` are the broken forms.
    const sourceOf = async (
      name: (typeof FRIDA_SCRIPT_PRESETS)[number]["name"],
    ) => {
      const read = await readFridaScriptPreset(name, "test");
      if (!read.ok) throw new Error("preset unreadable");
      return read.value.source;
    };
    for (const preset of FRIDA_SCRIPT_PRESETS) {
      const source = await sourceOf(preset.name);
      expect(source, `${preset.name}: ObjC.intercept`).not.toMatch(
        /ObjC\.intercept/u,
      );
      expect(
        source,
        `${preset.name}: ObjC.implement must take a method object, not a class`,
      ).not.toMatch(/ObjC\.implement\(\s*(?!method\b)/u);
      const objc = objcRegion(source);
      if (objc === null) continue;
      expect(
        objc,
        `${preset.name}: an Objective-C implementation slot takes a pointer built by ObjC.implement`,
      ).not.toMatch(/\.implementation\s*=\s*function\b/u);
      const shape = OBJC_HOOK_SHAPES[preset.name];
      if (shape === undefined)
        throw new Error(
          `${preset.name}: declare the documented hook shape this preset uses`,
        );
      expect(objc, `${preset.name}: documented hook shape`).toMatch(shape);
      if (!/ObjC\.implement\(/u.test(objc)) continue;
      // A replaced method's id parameter is a raw pointer: it has to be read
      // back through ObjC.Object before any comparison, never stringified.
      const conversion = OBJC_ID_CONVERSION[preset.name];
      if (conversion === undefined)
        throw new Error(
          `${preset.name}: declare how its replaced method reads its id argument`,
        );
      expect(
        objc,
        `${preset.name}: id argument read through ObjC.Object`,
      ).toMatch(conversion);
      expect(
        objc,
        `${preset.name}: a raw id is not a path until it is wrapped`,
      ).not.toMatch(/String\(\s*path\s*\)/u);
      // The saved original keeps the untouched pointer.
      expect(objc, `${preset.name}: original receives the raw pointer`).toMatch(
        /oldImpl\(\s*self\s*,\s*sel\s*,\s*path\s*\)/u,
      );
    }
  });

  it("keeps the Java and C hook idioms the bridge documents", async () => {
    const ssl = await (async () => {
      const read = await readFridaScriptPreset("ssl-unpinning", "test");
      if (!read.ok) throw new Error("preset unreadable");
      return read.value.source;
    })();
    // Java methods take a plain replacement function.
    expect(ssl).toMatch(
      /CertificatePinner\.check\.overload[\s\S]*?\.implementation = function/u,
    );
    // The iOS hook attaches to the exported trust function and replaces its result.
    expect(ssl).toMatch(
      /Module\.findExportByName\(null, "SecTrustEvaluateWithError"\)/u,
    );
    expect(ssl).toMatch(
      /Interceptor\.attach\(evaluate, \{[\s\S]*?retval\.replace\(/u,
    );
  });

  it("declares only surfaces its own source names", async () => {
    for (const preset of FRIDA_SCRIPT_PRESETS) {
      const read = await readFridaScriptPreset(preset.name, "test");
      if (!read.ok) throw new Error("preset unreadable");
      for (const method of preset.detectedMethods)
        expect(
          read.value.source.includes(method),
          `${preset.name} declares ${method}, which its source never names`,
        ).toBe(true);
    }
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
