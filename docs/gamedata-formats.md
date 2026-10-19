# Game engine container formats (structure-only)

The `src/gamedata/` provider and `src/domain/gamedata/` parsers report container
structure only: indexes, chunk maps, and detection headers. They never decrypt,
never handle keys, and never decode asset contents. Encrypted sections are
reported as typed unknowns carrying the phrase **"encrypted (caller-supplied key
not read)"**, and file bodies are never decompressed, transformed, or extracted
beyond the single optional Godot entry fact described below.

Five tools share one provider identity (`game-data-structure`):

| Tool                              | Input                                  | Reports                                                                                           |
| --------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `inspect_godot_pck`               | one `.pck` file or embedded executable | v1/v2 header, engine version, flags, file_base, directory index entries, optional extraction fact |
| `inspect_vpk_archive`             | one `_dir.vpk` (or single-file VPK)    | header, v2 section sizes, full extension/path/name tree with CRCs and archive indices             |
| `inspect_gamemaker_data`          | one `data.win` / `game.unx`            | FORM chunk map, fixed GEN8 prefix fields, CODE/STRG/TXOR/SOND presence byte ranges                |
| `inspect_rpa_archive`             | one `.rpa` (RPA-3.0, RPA-2.0)          | header offset/key, deobfuscated index segments per entry, prefix presence                         |
| `inspect_rpgmaker_asset_prefixes` | one directory                          | per-file RPGMV fake-header detection with verbatim hex, unencrypted kind comparison               |

## Godot PCK (`inspect_godot_pck`)

Header resolution (Godot `core/io/file_access_pack.cpp`, engine 4.3 sources):

- Magic `GDPC` (u32 `0x43504447`) at offset 0 for standalone packs, or at the
  embedded-footer position: the last 4 bytes are `GDPC`, the u64 before them is
  the pack size, and the pack header starts at `end - size - 12`.
- Version 1 (Godot 3.x): after engine major/minor/patch comes the file count
  directly; entries carry no flags and offsets are absolute.
- Version 2 (Godot 4.x): pack flags (`bit0` directory encrypted,
  `bit1` relative file_base), u64 file_base, 64 reserved bytes, then the count.
  Stored entry offsets are resolved as `file_base + stored` (adjusted by the
  pack start when `rel_filebase`), and each entry carries an extra u32 flags
  field (`bit0` body encrypted).
- Versions 3 and 4 exist only in unreleased Godot builds and are reported as
  unsupported versions, not parsed.

The directory index (file count plus entries: path length, path, stored offset,
size, 16-byte MD5, flags) is projected verbatim; entries are never read,
decompressed, or decrypted. Pack formats v1/v2 define no compressed-body flag,
so sizes are on-disk byte counts. An encrypted directory is a typed unknown that
keeps the directory offset but no counts.

Optional bounded extraction: one entry whose path matches exactly, not flagged
encrypted, at most 128 MiB, written with an exclusive create into an existing
caller directory. The fact returned is the output path, byte count, and sha256,
plus whether the computed MD5 matches the index value. No engine or asset
format is decoded afterward.

## Source VPK (`inspect_vpk_archive`)

Header (Valve VPK format, Directory file):

- Signature `0x55aa1234`, version u32, tree size u32; version 2 adds four
  section sizes (file data, archive MD5s, other MD5s, signature).
- The three-level tree is null-terminated strings grouped by extension, then
  directory path, then file name; each empty string terminates its level.
- Each file entry: CRC32 u32, preload bytes u16, archive index u16, entry
  offset u32, entry length u32, terminator `0xffff`, then inline preload bytes.
  `0x7fff` archive index means the data follows the directory itself; total size
  is `preload + entry_length`.

Inventory only: the report enumerates entries with canonical
`dir/name.ext` paths (archive-relative identity is
`(archive_index, entry_offset, entry_length)`), never opens companion
`NNN.vpk` parts, and never reads preload contents. The pre-2009 headerless
layout is refused as unsupported.

## GameMaker data.win / game.unx (`inspect_gamemaker_data`)

- FORM header: magic `FORM`, u32 form size, then a sequence of
  `fourcc + u32 size + payload` chunks tiled to the form end. The walk refuses
  to invent chunks: a non-ASCII fourcc or an overrunning size stops the walk
  and the trailing bytes stay unexplained.
- GEN8 fixed prefix (first chunk), 44 examined bytes: debugger-disabled byte,
  bytecode version byte, padding u16, file-identification and config string
  pointers (resolved as FORM-relative `u32 length + UTF-8 bytes`; null
  pointers, out-of-range pointers, and invalid UTF-8 stay unresolved
  observations), last object id, last tile id, game id, 16-byte DirectPlay
  GUID, and the game-name string pointer. Deeper GEN8 fields remain unknown.
- Presence byte ranges for `CODE`, `STRG`, `TXOR`, and `SOND` are projected
  alongside the complete chunk inventory; presence is not identity.

## Ren'Py RPA (`inspect_rpa_archive`)

- RPA-3.0 header: `RPA-3.0 ` + 16 hex index-offset digits + space + 8 hex key
  digits + newline. RPA-2.0: `RPA-2.0 ` + 16 hex digits + newline.
- The index at the offset is a zlib stream (bounded) around a pickle in the
  exact shape Ren'Py uses: one dict mapping path strings to lists of 2-tuples
  `(offset, length)` or 3-tuples with an inline byte prefix. Evaluation uses a
  bounded safe-opcode subset (see `parseRpaPickleIndex`); any other opcode is a
  typed unknown with the refused opcode named — the stream is never executed by
  a real unpickler.
- Entry values are XOR-deobfuscated with the header key. This is index-table
  arithmetic only; bodies are never read or transformed. The archive-level
  `encrypted` flag records obfuscation (key != 0); the format has no per-body
  encryption field, so body secrecy stays unknown. Prefix segments report
  presence and length only.

## RPG Maker MV/MZ asset prefixes (`inspect_rpgmaker_asset_prefixes`)

- Candidate files (`.png`, `.ogg`, `.oga`, `.m4a`) are scanned recursively
  (bounded depth and count, symlinks skipped, unreadable paths preserved); each
  candidate gets exactly one bounded 24-byte head read.
- An encrypted asset is detected by the 16-byte fake header starting with
  `RPGMV`; the header hex and the following eight bytes are reported verbatim.
  Those following bytes are the original file's own header (for PNG,
  `89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52`); this tool reports,
  classifies (a restored `\x89PNG` magic guesses PNG and `OggS` guesses Ogg;
  anything else stays unknown), and never strips or reconstructs anything.
  Unencrypted PNG/OggS signatures are classified for comparison.
- No file digests are computed; per-file identity is its byte count under the
  selected directory.

## Paging and bounds

Long inventories page deterministically: Unicode-code-point ordered entry
tables, `entries_start`/`entries_limit` inputs (default page 200, maximum 500),
and exact `entry_total`/`entry_returned`/`complete` slices. Parser bounds are
real format/parse constraints (entry-count walk bounds, tree and index
decompression caps, entry-path length guards) and are reported as typed errors,
not silent truncation.

## Verification status

Parity tests use hand-built fixtures for PCK v1/v2, the embedded-footer layout,
the encrypted-directory flag, VPK v1/v2 trees, FORM/GEN8 structures, RPA-2.0/3.0
indexes (including XOR obfuscation and prefix segments), and RPG Maker fake
headers. No real engine-produced `.pck`, `pak01_dir.vpk`, `data.win`, `.rpa`,
or shipped encrypted game assets were parsed, and no engine was downloaded;
behavior against real commercial payloads is unverified. The Godot v3/v4
formats are recognized but intentionally unsupported.
