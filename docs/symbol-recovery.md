# Symbol recovery (GoReSym, rustfilt, dump_syms)

Three tools recover symbol facts for **stripped or partially stripped**
binaries without executing them. Each tool resolves its own caller-supplied
executable and fails closed with the exact setting and remediation.

| Tool                    | Producer  | Question it answers                                                                |
| ----------------------- | --------- | ---------------------------------------------------------------------------------- |
| `recover_go_symbols`    | GoReSym   | Which Go functions, entries, sizes, module, and Go version does this binary carry? |
| `demangle_rust_name`    | rustfilt  | What do these mangled Rust names demangle to?                                      |
| `generate_symbol_table` | dump_syms | What MODULE/FUNC/PUBLIC/FILE facts does a Breakpad table contain?                  |

## Configuration

| Setting                 | Meaning                                                                    |
| ----------------------- | -------------------------------------------------------------------------- |
| `REA_GORESYM_COMMAND`   | **Required** for `recover_go_symbols`. Absolute path to GoReSym.           |
| `REA_RUSTFILT_COMMAND`  | Optional absolute path to rustfilt. Unset resolves `rustfilt` from `PATH`. |
| `REA_DUMP_SYMS_COMMAND` | **Required** for `generate_symbol_table`. Absolute path to dump_syms.      |

REA never installs, downloads, or updates these tools. The GoReSym and
dump_syms lanes have no `PATH` fallback. rustfilt is commonly installed on
`PATH`, so an unset setting resolves the first executable named `rustfilt`.

The session inventory reports each tool separately. A tool whose executable is
missing is unavailable while the others remain usable.

## What reaches Evidence

`recover_go_symbols` reports the target path, size, SHA-256, Go version,
architecture, operating system, module path, and a bounded function table of
name, entry offset, and size.

`demangle_rust_name` pairs each caller-supplied name with its demangled form,
or null when the demangler leaves it unchanged.

`generate_symbol_table` reports the Breakpad MODULE identity, bounded FUNC rows
(name, address, size, parameter size), and PUBLIC and FILE counts. The full
symbol text stays out of Evidence.

Unrecognized rows are counted, not guessed. Truncation is explicit, and
`coverage` reports `partial` whenever a bound or an unparsed row applies.

The producer argv and output shapes in this lane are documented assumptions; no
verified release of any of the three tools is pinned yet.
