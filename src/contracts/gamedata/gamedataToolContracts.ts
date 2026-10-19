import {
  inspectGodotPckInputSchema,
  godotPckReportSchema,
} from "../../domain/gamedata/godotPck.js";
import {
  inspectVpkArchiveInputSchema,
  vpkReportSchema,
} from "../../domain/gamedata/vpkArchive.js";
import {
  inspectGamemakerDataInputSchema,
  gamemakerReportSchema,
} from "../../domain/gamedata/gamemakerData.js";
import {
  inspectRpaArchiveInputSchema,
  rpaReportSchema,
} from "../../domain/gamedata/rpaArchive.js";
import {
  inspectRpgmakerAssetPrefixesInputSchema,
  rpgmakerReportSchema,
} from "../../domain/gamedata/rpgmakerAssets.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * Structure-only game-container inspection: pack and archive indexes, chunk
 * maps, and detection headers. Encrypted sections are typed unknowns and no
 * file body is ever decoded, decrypted or stripped.
 */
export const GAME_DATA_TOOL_CONTRACTS = [
  {
    name: "inspect_godot_pck",
    ...toolContractMetadata("inspect_godot_pck"),
    description:
      "Inspect a Godot pack (PCK v1/v2, standalone or embedded behind the GDPC footer trailer): engine version, pack flags, file_base, and the readable directory index — entry paths, stored and resolved data offsets, sizes, and index MD5 values. An encrypted directory is reported as a typed unknown ('encrypted (caller-supplied key not read)') with the directory offset; encrypted body flags are reported per entry. Optional bounded single-entry extraction with sha256 of the verbatim body (refuses encrypted entries and existing output paths); bodies are never decompressed or decoded. Formats v3/v4 are reported as unsupported versions.",
    kind: "artifact-provider",
    inputSchema: inspectGodotPckInputSchema,
    outputSchema: evidenceResultOf(godotPckReportSchema),
    examples: [
      { title: "Index a standalone pack", input: { path: "/tmp/game.pck" } },
      {
        title: "Page entries and extract one file verbatim",
        input: {
          path: "/tmp/game.pck",
          entries_start: 200,
          entries_limit: 100,
          extract: {
            entry_path: "scripts/global.gdc",
            output_directory: "/tmp/rea-pck-extracts",
          },
        },
      },
    ],
  },
  {
    name: "inspect_vpk_archive",
    ...toolContractMetadata("inspect_vpk_archive"),
    description:
      "Inspect a Source-engine VPK directory file (signature 0x55aa1234, versions 1 and 2): header and section sizes, and the full directory tree — extension/path/name walk with per-entry CRC32, preload byte counts, archive index (0x7fff means data follows the directory), entry offsets and lengths. Inventory only: companion _NNN.vpk archive parts are never opened and preload contents are never read.",
    kind: "artifact-provider",
    inputSchema: inspectVpkArchiveInputSchema,
    outputSchema: evidenceResultOf(vpkReportSchema),
    examples: [
      {
        title: "Walk the directory tree",
        input: { path: "/tmp/game/pak01_dir.vpk" },
      },
    ],
  },
  {
    name: "inspect_gamemaker_data",
    ...toolContractMetadata("inspect_gamemaker_data"),
    description:
      "Inspect a GameMaker data.win or game.unx file: the FORM chunk walk (fourcc, offset, byte range for every top-level chunk), the fixed GEN8 prefix (debugger flag, bytecode version, file identification, config, and game-name string pointers, last object/tile ids, game id, DirectPlay GUID), and presence byte ranges for CODE/STRG/TXOR/SOND. Chunk contents are untouched — a structure map, not a decompiler.",
    kind: "artifact-provider",
    inputSchema: inspectGamemakerDataInputSchema,
    outputSchema: evidenceResultOf(gamemakerReportSchema),
    examples: [
      { title: "Map the chunk layout", input: { path: "/tmp/game/data.win" } },
    ],
  },
  {
    name: "inspect_rpa_archive",
    ...toolContractMetadata("inspect_rpa_archive"),
    description:
      "Inspect a Ren'Py RPA-2.0 or RPA-3.0 archive: header (offset and XOR key), the zlib-compressed pickle index evaluated through a bounded safe-opcode subset, and the deobfuscated entry table — per-file segments with stored (obfuscated) and XOR-deobfuscated offsets and lengths, plus inline-prefix presence. Index arithmetic only: file bodies are never read or transformed, and refusal of unsupported pickle opcodes is a typed unknown, never an evaluation.",
    kind: "artifact-provider",
    inputSchema: inspectRpaArchiveInputSchema,
    outputSchema: evidenceResultOf(rpaReportSchema),
    examples: [
      {
        title: "Read the archive index",
        input: { path: "/tmp/game/archive.rpa" },
      },
    ],
  },
  {
    name: "inspect_rpgmaker_asset_prefixes",
    ...toolContractMetadata("inspect_rpgmaker_asset_prefixes"),
    description:
      "Detect RPG Maker MV/MZ encrypted-asset fake headers (the 16-byte RPGMV prefix) across a caller-selected directory of PNG/OGG/OGA/M4A candidates: per-file presence, the verbatim 16-byte header hex, and the eight bytes after it — detecting, never stripping or decrypting. Unencrypted PNG/OggS signatures are classified for comparison. Bounds: recursion depth, candidate count, and one 24-byte head read per file.",
    kind: "artifact-provider",
    inputSchema: inspectRpgmakerAssetPrefixesInputSchema,
    outputSchema: evidenceResultOf(rpgmakerReportSchema),
    examples: [
      {
        title: "Scan a game's assets directory",
        input: { directory: "/tmp/game/assets" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
