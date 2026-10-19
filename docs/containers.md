# Container inspection

The `containers` family covers three read-only, structure-only container
formats: browser-extension packages (CRX3, Firefox XPI) and PyInstaller
CArchive/PYZ archives. All three operations are offline: they never execute
target code, never access the network, never decompress or decrypt entry
payload contents, and never verify signatures.

| Tool (MCP)                    | CLI command                   | Target                                              |
| ----------------------------- | ----------------------------- | --------------------------------------------------- |
| `inspect_crx_extension`       | `inspect-crx-extension`       | Chromium CRX3 package (`.crx`)                      |
| `inspect_xpi_extension`       | `inspect-xpi-extension`       | Firefox XPI package (`.xpi`)                        |
| `inspect_pyinstaller_archive` | `inspect-pyinstaller-archive` | PyInstaller onefile executable or bare PKG/CArchive |

## CRX3 (`inspect_crx_extension`)

Follows the public
[crx3.proto](https://source.chromium.org/chromium/chromium/src/+/main:components/crx_file/crx3.proto)
layout: `Cr24` magic, version 3, a little-endian header length, the protobuf
`CrxFileHeader`, then the ZIP archive.

- Header facts are reported as metadata: `proof` entries
  (`sha256_with_rsa` / `sha256_with_ecdsa`) list public-key byte counts,
  public-key SHA-256 digests, and signature byte counts. Signature
  **validity is deliberately not verified**.
- `crx_id` is derived only from a single Sha256WithRsa proof (first 128 bits
  of the proof's public-key SHA-256, Chromium's developer-key convention).
  Absent or multiple proofs leave it `null`. Unrecognized header fields are
  counted and reported.
- The exact ZIP payload `archive_offset` is reported so downstream tools can
  hand the inner archive bytes to the trusted ZIP reader (`ZipArtifactReader`).
  To project the extension manifest surface, the payload is streamed once into
  an owned owner-only temporary root (bounded to 256 MiB) and enumerated there;
  manifest.json is read with a 4 MiB budget.
- The manifest surface is value-free extension metadata feeding the JS plane:
  `name`, `version`, `manifest_version`, `permissions`,
  `host_permissions`, `background.service_worker`, MV1/MV2
  `background.scripts`, `content_scripts[].matches/js/css`, and
  `browser_specific_settings.gecko`. Unrecognized top-level members are
  counted, not interpreted.

**Boundaries.** Header section ≤ 1 MiB, manifest.json ≤ 4 MiB, ZIP entries
enumerated under the shared decompression budget with a 262144-entry cap.
Malformed, truncated, or oversized inputs produce typed refusals
(`AnalysisInputError` / `AnalysisResourceConstraintError`), never partial
guesses.

## XPI (`inspect_xpi_extension`)

A Firefox XPI is a ZIP package read directly through the trusted archive
reader.

- `META-INF/manifest.mf` and `META-INF/mozilla.sf` are parsed for per-entry
  SHA1 digest facts and digest-over-manifest presence (JAR-manifest text,
  including continuation-line wrapping). Digest values are observed metadata;
  **entry-digest and JAR signature validity are not verified**.
- Other `META-INF` signature artifacts (`.sf`, `.rsa`, `.ec`, `.sig`) are
  listed by name and declared size only.
- The same value-free manifest surface as CRX3 is projected, including the
  gecko browser-specific settings (`id`, `strict_min_version`).

## PyInstaller (`inspect_pyinstaller_archive`)

Follows `PyInstaller/archive/readers.py` and the dual-cookie layout popularized
by pyinstxtractor:

- The `MEI\x0c\x0b\x0a\x0b\x0e` cookie is located by a bounded backward scan
  from EOF. Both cookie layouts are parsed: 24 bytes (`!8sIIII`, PyInstaller
  2.0) and 88 bytes (`!8sIIII64s`, 2.1+, detected via the 64-byte Python
  library name probe).
- CArchive TOC entries carry `entry_length`, absolute `position`,
  `compressed_size`, `uncompressed_size`, `compressed`, `typecode` (with a
  per-code label), and the NUL-padded UTF-8 name (undecodable names keep a
  raw-byte fact). `encrypted` is always reported `false` with a global
  limitation: the TOC format has no per-entry encryption flag, and contents
  are **never decrypted**.
- Embedded PYZ archives (TOC type codes `z`/`Z`, first 16) report their pyc
  magic bytes, TOC position, and the marshaled TOC entries
  (`name`, `item_type` module/package/data/namespace-package, relative
  `position`, `length`). The marshal reader is a bounded minimal subset
  (dict before PyInstaller 3.1, list-of-tuples since): it mirrors CPython's
  wire encoding for the shapes ZlibArchive writes, including `TYPE_REF`
  resolution, with 16 MiB / 262144-object / 128-depth budgets. A malformed or
  over-bounded marshal TOC is a contained limitation on that PYZ record, not a
  whole-operation failure.
- pyc header facts (folded into module entries, TOC codes `m`/`M`/`s` whose
  bytes are uncompressed): the CPython 3.7–3.13 release-line magic map, the
  PEP 552 hash-based and check-source flags, and either timestamp/source-size
  or the 8-byte source hash. Pre-3.7 headers and PyInstaller ≥ 5.3
  header-stripped module data are reported opaque. Unknown magic numbers stay
  unknown (`null` version with a limitation).

Entry positions are absolute file offsets, so callers can read raw entry bytes
with existing offset-based tools. A future bounded single-entry extraction can
be added on the same positions without changing the index contract.

## Safari `.appex`

A `.appex` input is an Apple bundle, not a container this family parses. The
XPI operation detects the suffix and defers: "use the existing Apple
application-bundle analysis (`project_apple_application_graph`)". The Apple
bundle lane owns bundle anatomy and plist parsing.

## Ownership and limits

- Every operation is Evidence-wrapped with the `containers` provider identity
  and records file-offset locations (CRX archive offset; PyInstaller cookie
  offset).
- Cleanup failures of the owned temporary root or descriptors are reported as
  unresolved resources via `ProviderCleanupError`, retaining the completed
  observation as partial Evidence. The failed owners (descriptor, ZIP reader,
  or private temporary root) are also adopted into the service's retained
  resource set and retried through the service's `close()`, so a later close
  either confirms their release or reports the exact remaining resources.
- Limits declared here are format/resource bounds, not agent budgets: CRX3
  header 1 MiB, temp payload copy 256 MiB, extension manifest 4 MiB, JAR
  digest manifests 16 MiB, PYZ TOC 16 MiB, CArchive TOC 64 MiB, marshal
  entries 16 MiB / 262144 objects / 1 MiB strings / depth 128. The owning
  constants live in `src/domain/containers/` (`crxHeader.ts`,
  `webExtensionManifest.ts`, `jarManifestDigests.ts`, `pyzToc.ts`,
  `pyinstallerArchive.ts`) and `ContainerInspectionService.ts`.
