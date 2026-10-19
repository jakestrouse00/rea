import { describe, expect, it } from "vitest";

import { inspectGamemakerDataInputSchema } from "../../domain/gamedata/gamemakerData.js";
import { inspectGodotPckInputSchema } from "../../domain/gamedata/godotPck.js";
import { inspectRpaArchiveInputSchema } from "../../domain/gamedata/rpaArchive.js";
import { inspectRpgmakerAssetPrefixesInputSchema } from "../../domain/gamedata/rpgmakerAssets.js";
import { inspectVpkArchiveInputSchema } from "../../domain/gamedata/vpkArchive.js";
import { gamedataOperationNames } from "../../domain/gamedata/gamedataRequests.js";
import { GAME_DATA_TOOL_CONTRACTS } from "./gamedataToolContracts.js";

/** Domain input schemas, keyed by the owning public operation name. */
const domainInputSchemas: Readonly<Record<string, unknown>> = {
  inspect_godot_pck: inspectGodotPckInputSchema,
  inspect_vpk_archive: inspectVpkArchiveInputSchema,
  inspect_gamemaker_data: inspectGamemakerDataInputSchema,
  inspect_rpa_archive: inspectRpaArchiveInputSchema,
  inspect_rpgmaker_asset_prefixes: inspectRpgmakerAssetPrefixesInputSchema,
};

describe("gamedataToolContracts", () => {
  it("declares the five named game-data contracts exactly once each", () => {
    expect(GAME_DATA_TOOL_CONTRACTS.map(({ name }) => name)).toEqual([
      ...gamedataOperationNames,
    ]);
    expect(new Set(GAME_DATA_TOOL_CONTRACTS.map(({ name }) => name)).size).toBe(
      GAME_DATA_TOOL_CONTRACTS.length,
    );
  });

  it("binds every contract to its owning domain input schema", () => {
    for (const contract of GAME_DATA_TOOL_CONTRACTS) {
      expect(
        contract.inputSchema,
        `${contract.name} must bind its owning domain input schema`,
      ).toBe(domainInputSchemas[contract.name]);
    }
  });

  it("keeps inputs and outputs self-contained without $ref indirection", () => {
    for (const contract of GAME_DATA_TOOL_CONTRACTS) {
      expect(JSON.stringify(contract.inputSchema)).not.toContain("$ref");
      expect(JSON.stringify(contract.outputSchema)).not.toContain("$ref");
    }
  });
});
