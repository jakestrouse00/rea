# Rust binary dependency metadata

`inspect_rust_binary` / `inspect-rust-binary` answers which crate names,
versions, sources, and dependency edges are embedded by cargo-auditable in one
selected local executable or library. It reads the file without running it and
requires no Rust installation, active binary target, Hopper, Ghidra, or IDA.

```bash
rea inspect-rust-binary /absolute/path/to/application --json
```

The CLI resolves relative paths against the caller's working directory. MCP
requires an absolute filesystem path and preserves that exact selection:

```json
{
  "name": "inspect_rust_binary",
  "arguments": { "path": "/artifacts/application" }
}
```

## Observations

The inline Evidence result contains the artifact path, SHA-256, byte length,
container format, architecture, word size, and byte order. When a `.dep-v0`
section is present, `auditable_metadata` contains:

- `section_name`, `.dep-v0` for ELF and PE or `__DATA,.dep-v0` for thin Mach-O;
- `file_offset` and `section_bytes`, the exact file range of the compressed section;
- `compressed_bytes` and `uncompressed_bytes`;
- `format_version`, the embedded integer, or `null` when the field is omitted;
- `packages`, in the section's original order, with `name`, `version`, `source`,
  `kind`, `dependencies`, and `root`;
- `root_package_index`, the single package marked `root`, or `null` when none is marked;
- `dependency_edges`, pairs of package indices in package-then-dependency order;
- `cyclic_dependency_indices`, sorted unique indices that participate in a cycle.

An omitted `kind` stays `null`. The embedded format treats that omission as
runtime, and that default is not stored in the section. An omitted dependency
list is an empty array. An omitted `root` flag is false.

`rustc_commit` is present only when a `/rustc/<40-hex>/` path is found in
read-only data. Its `evidence_kind` is `inferred`. The hash is not a claim that
that compiler produced the binary. Several distinct hashes leave a single
commit unknown.

## Limits and failures

The selected file is limited to 256 MiB. A dependency section is limited to 1
MiB compressed. Inflated JSON is limited to the smaller of 8 MiB and 64 times
the compressed size. The complete report is limited to 8 MiB. Empty sections,
truncated or trailing zlib bytes, invalid JSON, unknown fields, dependency
indices outside the package list, more than one root package, and compressed
dependency sections are typed failures. A cycle is reported and is not walked.

A missing section returns success with `auditable_metadata: null` and a
limitation. Absence of `.dep-v0` does not mean the binary has no dependencies.
Unknown embedded format revisions are retained in `format_version` and
interpreted using the highest known preceding revision, following the
cargo-auditable schema. The output includes a limitation that identifies this
fallback and notes that the particular revision has not been independently
verified. An omitted revision remains `null` and follows revision 0 semantics.
Embedded names and versions are file content. They do not authenticate the
packages or the compiler.

Universal Mach-O containers are unsupported. Select a thin slice first. ELF,
PE, and thin Mach-O are the supported containers.

Package and dependency counts are checked against the minimum required JSON
representation before graph allocation or schema cloning. Oversized graphs
report the output byte budget; the compiler-path capacity reports
`maximum_rustc_hashes` in hashes, independently of byte limits.

## Symbol table inspection

`inspect_rust_symbols` / `inspect-rust-symbols` answers which symbols one
selected local ELF or thin Mach-O image declares for linking, with inline Rust
name demangling. It reads the file without running it and requires no Rust
installation, active binary target, Hopper, Ghidra, or IDA.

```bash
rea inspect-rust-symbols /absolute/path/to/application --offset 0 --limit 50 --json
```

ELF images are read through `.symtab` when present, otherwise `.dynsym`. Thin
Mach-O images are read through `LC_SYMTAB` nlist entries. PE symbol tables are
not read: the report keeps `table: null` with a limitation rather than
claiming an examined table.

Each entry keeps:

- `index`, the zero-based position of the symbol within its table;
- `mangled`, the exact symbol-table name;
- `format`, the detected Rust mangling scheme: `legacy` (`_ZN…E`), `v0`
  (`_R…`), or `other` for names that use no Rust scheme, including plain C and
  C++ names;
- `demangled` and `demangle_failure_reason`, one non-null and one null; the
  legacy trailing hash element (`h` followed only by hex digits, in any
  length) is trimmed, mirroring rustc-demangle's hash recognition;
- `value_hex`, the symbol value in lowercase hexadecimal;
- `size`, the declared symbol size, or null where the table stores none;
- `binding`, one of `local`, `global`, `weak`, `unknown`;
- `section_index`, the section index a defined symbol binds to; undefined
  symbols stay null and out-of-table indices are preserved as facts;
- `file_offset`, mapped from the symbol value through file-backed segments,
  or null when the value is unmapped, ambiguous, or inside uninitialized
  memory.

The report returns the requested page (`offset`, `limit`, `entries`) plus
summary counts: `declared_symbols` and `named_symbols` over the full table,
`mangled_legacy`, `mangled_v0`, and `mangled_other` classified across the full
table, `complete` stating whether every declared named symbol was examined,
and `demangled_ok` / `demangled_failed` for the returned page.

### Limits and failures

Pages are bounded to 500 entries with a default of 50. Every table is
admitted to 200000 symbols; tables declaring more are reported with
`complete: false` and examined up to that bound instead of failing.
Demangling bounds each mangled input to 16384 bytes and each rendered name to
16384 characters; failures become per-entry reasons and never fail the page.
Truncated names, name offsets outside a string table, more than one symbol
table or `LC_SYMTAB`, symbol-table links to non-string tables, and ranges
outside the file are typed failures.

Both symtab and dynsym are detected on ELF; only the primary table's page is
returned so paging stays reproducible, and the presence of the second table is
reported through the limitations. Symbol names are file content; they do not
authenticate packages or a compiler, and C++ names in mixed binaries may carry
the legacy classification because both schemes start with `_ZN`.

Demangling coverage is validated against a golden corpus of v0 symbols taken
from the rustc book's annotated examples and real-world legacy symbols. Deeply
nested generics, punycode identifiers, closure and shim namespaces, generic
argument substitution, and vendor-specific suffixes are covered. The 32-bit
and 64-bit symbol-table readers are validated against synthetic ELF and
Mach-O fixtures; no compiled Rust toolchain fixture exists for this coverage,
so symbol-layout parsing has not been verified against a real rustc-produced
binary and remains explicitly unverified.
