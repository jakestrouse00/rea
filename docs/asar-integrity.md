# ASAR packed integrity and bytecode handoff

`inspect_asar_integrity` checks one local Electron `app.asar` against the
checksums its own header declares, then lists V8 bytecode members as candidates
for [`decompile_v8_bytecode`](v8-bytecode.md). It reads the archive and nothing
else: no member bytes are published, no archived code runs, and no Electron fuse
or signing state is asserted.

```json
{
  "name": "inspect_asar_integrity",
  "arguments": {
    "path": "/Applications/Example.app/Contents/Resources/app.asar"
  }
}
```

## What is checked

Modern `@electron/asar` headers carry a per-member `integrity` object:
`algorithm` (`SHA256`), the whole-member `hash`, `blockSize`, and the `blocks`
array of per-block hashes. REA reads that declaration from the same header the
ASAR reader already decodes, then streams the member's packed bytes and
recomputes both values with the writer's block boundaries.

The result reports:

| Field                                                                          | Meaning                                                                                                                                                                       |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sha256`, `bytes`                                                              | Digest and size of the archive itself.                                                                                                                                        |
| `container.header_bytes`, `files`, `directories`, `symlinks`, `unpacked_files` | Header extents and member counts.                                                                                                                                             |
| `integrity.members_declaring`                                                  | Packed members that declare a checksum.                                                                                                                                       |
| `integrity.members_verified`, `members_mismatched`                             | Members whose declared whole-member hash and every declared block hash matched, or did not.                                                                                   |
| `integrity.members_without_checksums`, `members_unverified`                    | Members with no usable declaration, and declared members that were not checked.                                                                                               |
| `integrity.mismatched_paths`                                                   | Up to 50 mismatching member paths. Counts stay complete.                                                                                                                      |
| `integrity.verified_bytes`, `truncated`                                        | Bytes actually read, and whether the selected budget stopped the pass.                                                                                                        |
| `integrity.state`                                                              | `verified`, `mismatched`, `partial`, or `not_declared`. A mismatch is a finding in Evidence, not a tool failure.                                                              |
| `handoff.candidates`                                                           | Members whose path ends in `.jsc` or `.bytecode`, with size, unpacked marker and their integrity outcome. `sha256` stays `null` because classification reads no member bytes. |

`max_verify_bytes` (default 64 MiB, maximum 1 GiB) bounds the aggregate read.
Members past the budget, unpacked companions stored in `<archive>.unpacked`, and
members without a usable declaration are reported as `unverified` — absence of a
verification is never reported as validity. `max_candidates` (default 200,
maximum 2000) bounds the candidate list.

## Handoff to View8

`handoff.instruction` names the next step and the required
[`REA_VIEW8_COMMAND`](v8-bytecode.md#selecting-the-launcher). Publish the
candidate's bytes yourself (for example with the artifact extraction workflow or
by copying the member), then call `decompile_v8_bytecode` on that path. Suffix
selection is a hypothesis: a `.jsc` member may hold plain text or another
container, and only the V8 cached-data header check in that tool can tell you
otherwise.

## What this does not establish

- A verified archive says the bytes match the builder's own index. It does not
  establish that Electron loaded this archive, that
  `EnableEmbeddedAsarIntegrityValidation` is enabled, that `ElectronAsarIntegrity`
  in an app bundle's `Info.plist` names this archive's hash, or that a code
  signature is intact.
- A mismatch can come from a rebuild, a packer that rewrote the archive, or a
  hand-edited header. REA reports the outcome and the paths; it does not infer
  which happened.
- Symlinked members are counted but never followed, and their targets are not
  disclosed.
- The header is admitted under the same `asar.max_header_bytes` budget as static
  JavaScript analysis, so an oversized index refuses before any member is read.
