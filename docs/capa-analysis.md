# Capability matching (capa)

`analyze_binary_capabilities` matches [mandiant/capa](https://github.com/mandiant/capa)
rules against one **caller-held** local executable, library, or .NET assembly.
REA never installs capa, downloads rule sets, or executes the target.

## Configuration

| Setting            | Meaning                                                    |
| ------------------ | ---------------------------------------------------------- |
| `REA_CAPA_COMMAND` | **Required.** Absolute path to the caller's `capa` binary. |

`REA_CAPA_COMMAND` has no `PATH` fallback: an unset value is a typed
configuration refusal (`not_configured`) that names the setting and the
remediation. The provider asserts the client with `capa --version` before every
operation and records the recognized version in Evidence.

Install capa yourself, for example with `pip install flare-capa`; REA does not
run that command.

## Operation

| Tool                          | Question it answers                                                         |
| ----------------------------- | --------------------------------------------------------------------------- |
| `analyze_binary_capabilities` | Which capa rules match this binary, where, and under which ATT&CK/MBC refs? |

The request carries only `path`, an optional capa `backend` (its own names:
`vivisect`, `binja`, `ghidra`, `ida`, `dotnet`, `pefile`, or `default`), and
`max_rules`.

## What reaches Evidence

Every result reports:

- the target path, byte count, and SHA-256;
- the selected command and its version;
- each matched rule's name, namespace, scope, authors, ATT&CK and MBC
  references, match count, and bounded match locations;
- a covered/unparsed count so a partial inventory is visible.

It never reports decoded strings, matched bytes, or the rule source. Capa's
JSON document is parsed structurally; unrecognized rule or match rows are
counted, not guessed.

A match is rule-driven evidence. An absent rule is not proof that a behavior is
absent: the rule inventory, the selected backend, and capa's own analysis
limits all bound what can match.

The exact capa JSON fields this lane consumes are documented assumptions; no
capa release is pinned yet, and every result carries that note.
