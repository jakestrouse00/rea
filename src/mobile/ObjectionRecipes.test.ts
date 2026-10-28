import { describe, expect, it } from "vitest";

import {
  OBJECTION_RECIPES,
  findObjectionRecipe,
  objectionArguments,
  scrubObjectionOutput,
} from "./ObjectionRecipes.js";

const classesRecipe = findObjectionRecipe("list-loaded-classes")!;
const environmentRecipe = findObjectionRecipe("app-environment-names")!;

describe("objection recipe whitelist", () => {
  it("declares unique ids with fixed non-empty argv", () => {
    const seen = new Set<string>();
    for (const recipe of OBJECTION_RECIPES) {
      expect(seen.has(recipe.id)).toBe(false);
      seen.add(recipe.id);
      expect(recipe.argv.length).toBeGreaterThan(0);
      expect(recipe.argv.every((part) => part.length > 0)).toBe(true);
    }
    expect(OBJECTION_RECIPES.map(({ id }) => id).sort()).toEqual([
      "app-environment-names",
      "keystore-aliases",
      "list-activities",
      "list-loaded-classes",
    ]);
  });

  it("builds the target selector and run keyword around the recipe only", () => {
    expect(
      objectionArguments({
        recipe: classesRecipe,
        targetKind: "bundle",
        target: "com.example.app",
        serial: undefined,
      }),
    ).toEqual([
      "-g",
      "com.example.app",
      "run",
      "android",
      "hooking",
      "list",
      "classes",
    ]);
    expect(
      objectionArguments({
        recipe: classesRecipe,
        targetKind: "process",
        target: "example",
        serial: "emulator-5554",
      }),
    ).toEqual([
      "-n",
      "example",
      "-S",
      "emulator-5554",
      "run",
      "android",
      "hooking",
      "list",
      "classes",
    ]);
  });
});

describe("objection output scrubbing", () => {
  it("keeps class names and drops banners and free text", () => {
    const scrub = scrubObjectionOutput(
      classesRecipe,
      [
        "Using USB device `emulator-5554`",
        "Agent injected into target process for Android instrumentation",
        "com.example.net.NetClient",
        "com.example.net.NetClient",
        "com.example.db.Store",
        "some free-form diagnostic text",
      ].join("\n"),
      10,
    );
    expect(scrub.rows).toEqual([
      "com.example.net.NetClient",
      "com.example.db.Store",
    ]);
    expect(scrub.rowCount).toBe(2);
    expect(scrub.droppedLineCount).toBe(2);
    expect(scrub.unparsedLineCount).toBe(1);
    expect(scrub.rowsTruncated).toBe(false);
  });

  it("keeps environment keys and never their values", () => {
    const scrub = scrubObjectionOutput(
      environmentRecipe,
      ["Name: com.example.app", "Version: 1.4.2 secret-token-value"].join("\n"),
      10,
    );
    expect(scrub.rows).toEqual(["Name", "Version"]);
    expect(JSON.stringify(scrub)).not.toContain("secret-token-value");
    expect(JSON.stringify(scrub)).not.toContain("com.example.app");
  });

  it("bounds retained rows and reports the truncation", () => {
    const scrub = scrubObjectionOutput(
      classesRecipe,
      ["a.One", "a.Two", "a.Three", "a.Four"].join("\n"),
      2,
    );
    expect(scrub.rows).toEqual(["a.One", "a.Two"]);
    expect(scrub.rowCount).toBe(4);
    expect(scrub.rowsTruncated).toBe(true);
  });

  it("strips terminal colour codes before classifying a row", () => {
    const scrub = scrubObjectionOutput(
      classesRecipe,
      "\u001B[32mcom.example.Green\u001B[0m",
      10,
    );
    expect(scrub.rows).toEqual(["com.example.Green"]);
    expect(scrub.unparsedLineCount).toBe(0);
  });
});
