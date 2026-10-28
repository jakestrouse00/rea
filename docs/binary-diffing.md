# Binary diffing (BinDiff + BinExport)

Two tools cover provider-backed binary comparison and BinExport production.
REA ships neither BinDiff nor the BinExport Ghidra extension.

| Tool                        | Question it answers                                                           |
| --------------------------- | ----------------------------------------------------------------------------- |
| `diff_binaries`             | Which functions pair across two retained artifacts, and how similar are they? |
| `export_binexport_protobuf` | Produce a `.BinExport` protobuf for one artifact.                             |

## Configuration

| Setting                 | Meaning                                                                                      |
| ----------------------- | -------------------------------------------------------------------------------------------- |
| `REA_BINDIFF_COMMAND`   | **Required** for `diff_binaries`. Absolute path to a BinDiff adapter command.                |
| `REA_BINEXPORT_COMMAND` | **Required** for `export_binexport_protobuf`. Absolute path to a BinExport exporter command. |

Both are fail-closed. REA never downloads, installs, or builds either tool.

## `diff_binaries`

`diff_binaries` is a session tool. It takes two **retained `inspect_artifact`
observations** (not bare paths), resolves each subject, re-digests both files,
and refuses when either file no longer matches its retained observation. The
provider runs `REA_BINDIFF_COMMAND <primary> <secondary>` and reads the adapter
JSON on stdout:

```json
{
  "matches": [
    {
      "primary": { "address": "0x401000", "name": "main" },
      "secondary": { "address": "0x401020", "name": "main" },
      "similarity": 0.94,
      "confidence": 0.88
    }
  ],
  "unmatched_primary": 2,
  "unmatched_secondary": 1
}
```

`similarity` and `confidence` are clamped to `[0, 1]`. Rows that do not resolve
are counted as unparsed; a document with no recognizable match table is a
protocol error, not a partial success.

The Evidence reports each matched pair's addresses, names, similarity,
confidence, and a names-changed flag, plus unmatched counts. A pair is a
**static candidate**, never behavioral equivalence. This is a provider-backed
alternative to the bespoke `compare_functions` matcher, not a replacement:
use `diff_binaries` to select candidate pairs, then `analyze_function` and
`compare_functions` for selected pairs.

### Composition with `find_changed_behavior`

`diff_binaries` Evidence is a recognized comparison operation
(`rea.binary-diff`). Pass it to `find_changed_behavior` to obtain
`static_candidate` findings: changed pairs become `derived_relationship`
findings, low-confidence pairs become `unresolved_branch`, and unmatched
functions produce a coverage finding. Runtime observations remain separate.

## `export_binexport_protobuf`

The exporter runs `REA_BINEXPORT_COMMAND <path> <output_directory>` and must
write one `.BinExport` file into that directory. REA copies the file into one
new subdirectory of the caller's `output_directory` with mode `0600` and its
SHA-256, and refuses a file that does not start with the `BINE` magic.

## BinExport build recipe (Ghidra extension manager pattern)

This recipe is documented but **not executed by REA** and is unverified in this
environment. The extension follows the same installation shape as REA's own
Ghidra extensions: a caller-built JAR/ZIP installed through Ghidra's extension
manager and referenced by absolute path.

1. Install a JDK 17 and the Ghidra release that matches the chosen BinExport
   branch.
2. Clone the open-source BinExport repository:
   ```sh
   git clone https://github.com/google/binexport
   cd binexport/java
   ```
3. Build the extension ZIP with `GHIDRA_INSTALL_DIR` pointing at your Ghidra
   installation:
   ```sh
   GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew buildExtension
   ```
   The ZIP is written under `binexport/java/dist/`.
4. Install it with Ghidra's **File → Install Extensions…**, or unpack it under
   `$GHIDRA_INSTALL_DIR/Ghidra/Extensions`, then restart Ghidra.
5. Produce a `.BinExport` with the plugin's exporter (Ghidra's Export dialog or
   the headless `-postProcess`/`-postScript` hook your build ships). Wrap that
   invocation in an adapter command so REA can call it as
   `REA_BINEXPORT_COMMAND <path> <output_directory>`.
6. Produce the match table with BinDiff 8's open-source build and wrap its
   output in the adapter JSON documented above. BinDiff's native `.BinDiff`
   SQLite database is not parsed by REA.

Verify the adapter command and the Ghidra/plugin versions against your own
build; REA does not attest the exporter's build bytes.
