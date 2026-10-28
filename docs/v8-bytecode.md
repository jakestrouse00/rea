# V8 bytecode disassembly

`decompile_v8_bytecode` disassembles one local V8 cached-data file — the output
of [`bytenode`](https://github.com/bytenode/bytenode) and similar packers — through
a **caller-supplied** [View8](https://github.com/WithSecureLabs/view8) build that
carries its own patched V8 disassembler.

REA reports structure only. Disassembly text and any recovered JavaScript stay
out of Evidence: the result carries the artifact digest, the cached-data header
words, and the disassembly's SHA-256, byte count and line count. Reproduce the
text locally with the same launcher when you need to read it.

```json
{
  "name": "decompile_v8_bytecode",
  "arguments": { "path": "/absolute/path/to/app/main.jsc" }
}
```

## What the result reports

| Field                                                                     | Meaning                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `client.command`                                                          | The absolute launcher path that ran. `client.version` stays `null` because REA does not probe View8's version.                                                                                                                          |
| `sha256`, `bytes`                                                         | Digest and size of the selected cached-data file, read once under an owner-only descriptor.                                                                                                                                             |
| `container.state`                                                         | `recognized` when the first 24 bytes carry V8's cached-data marker, `unrecognized` otherwise. An unrecognized artifact is reported, never repaired.                                                                                     |
| `container.magic_hex`                                                     | The observed first header word in hexadecimal. Some V8 builds XOR the low bits of the marker with their external-reference count, so only the `0xc0de` marker bits are compared.                                                        |
| `container.version_hash`, `source_hash`, `flag_hash`, `snapshot_checksum` | The header words V8 writes for cached data. `version_hash` identifies the V8 version that produced the payload; a mismatch between it and the patched V8 inside the selected View8 build is the usual reason a disassembly looks wrong. |
| `container.declared_payload_bytes`                                        | The payload length the header declares.                                                                                                                                                                                                 |
| `container.observed_payload_bytes`, `payload_length_matches`              | What the file actually holds after the 24-byte header, and whether the declaration agrees. A `false` value means the file was truncated, appended to, or is not the cached data it claims.                                              |
| `disassembly.sha256`, `bytes`, `lines`, `empty`                           | Bounded facts about the disassembly stream. Text is not returned.                                                                                                                                                                       |
| `coverage`                                                                | `complete` only when the cached-data header was recognized and its declared payload length matches the file; `partial` otherwise. View8 declares no coverage of its own.                                                                |

## Selecting the launcher

```sh
export REA_VIEW8_COMMAND=/absolute/path/to/view8-launcher
```

The value must be an absolute path to an executable regular file. REA does not
search `PATH`, download, build, or update View8. An unset, relative, missing, or
non-executable selection is a typed `capability_unavailable` refusal that names
`REA_VIEW8_COMMAND` and the build recipe. `inspect_analysis_settings` reports
the selection as an operator-owned constraint, and `REA_VIEW8_COMMAND` is read
once at startup.

One invocation runs under a fixed **300-second** deadline with a **64 MiB**
stdout capture budget and a **64 MiB** input read allowance. Exceeding the
capture budget is a resource-constraint error naming that allowance; a killed
run is a timeout error naming the deadline. Neither is retried automatically.

## Build recipe (macOS, Linux)

View8 is not a pip package with a working prebuilt disassembler on macOS. It
needs V8 built with the bytecode-disassembler hooks it patches, so the launcher
is a local build. This recipe is documentation, not an installer: REA never
runs it.

1. **Toolchain.** Install the platform C++ toolchain and Python 3. On macOS that
   is the Xcode command-line tools plus the system Python 3; on Linux a C++17
   compiler and Python 3. `depot_tools` must be on `PATH`.
2. **Check out View8 and its V8 pin.**

   ```sh
   git clone https://github.com/WithSecureLabs/view8
   cd view8
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r requirements.txt
   ```

   Read the repository's `README.md` and build script for the V8 revision it
   pins; do not substitute a different V8 checkout, because the disassembler
   depends on that revision's bytecode table.

3. **Fetch and patch V8.**

   ```sh
   gclient config --unmanaged https://chromium.googlesource.com/v8/v8.git
   gclient sync --no-history
   # Apply the patches shipped with View8 to v8/ before building.
   ```

   The patch set enables the disassembler and the cached-data entry points
   View8 calls. Build for the architecture you will analyze on:

   ```sh
   # Apple silicon host, Intel and arm64 V8 builds are separate jobs.
   gn gen out/disasm --args='is_debug=false v8_enable_disassembler=true v8_enable_object_print=true v8_monolithic=true'
   ninja -C out/disasm v8_monolith
   ```

4. **Build View8 against that V8.** Follow the repository's `build_v8.py` (or
   the equivalent `CMakeLists.txt` target) so the Python extension links the
   V8 you just built. Point `V8_DIR` at the checkout when the script asks.
5. **Expose one executable path.** Either symlink `view8.py` into a wrapper that
   activates the virtualenv and adds the built extension to the loader path, or
   compile the standalone binary the repository provides:

   ```sh
   #!/bin/sh
   exec /Users/you/tools/view8/.venv/bin/python \
     /Users/you/tools/view8/view8.py "$@"
   ```

   ```sh
   chmod 0700 /Users/you/tools/view8/bin/view8
   export REA_VIEW8_COMMAND=/Users/you/tools/view8/bin/view8
   ```

6. **Verify outside REA.** Run the launcher against a known `.jsc` and confirm it
   prints a disassembly. Only then call `decompile_v8_bytecode`; a launcher that
   prints nothing is reported as empty instead of being retried.

Keep the built V8 outside the repository. REA does not vendor it, hash-pin it, or
ship it, so the selected V8 revision remains operator-owned and unobserved.

## Interpretation limits

- View8's command line and disassembly text are **documented assumptions**. No
  verified View8 release is pinned, and REA parses no disassembly text, so the
  reported line and byte counts describe the stream rather than its content.
- The cached-data header decode is REA's own and is not verified against a
  specific V8 build. A recognized marker does not prove that this V8 produced
  the payload, that the embedded source is recoverable, or that the selected
  patched V8 revision matches `version_hash`.
- A disassembly is not recovered source. Bytecode may be optimized, inlined, or
  stripped of names, and bytenode payloads routinely omit the original file name.
- A `.jsc` file may hold plain text or another container. REA reports
  `container.state = unrecognized` and leaves the interpretation to you.
- The digest and the file View8 actually read are not attested as the same
  bytes: View8 receives the path, not the digest. Keep the artifact stable for
  the duration of the call.

## Related tooling

Use [`inspect_asar_integrity`](asar-integrity.md) on a packaged `app.asar` to
list `.jsc` and `.bytecode` members as candidates, together with their
header-declared integrity outcomes, before extracting any bytes for this tool.
