# YARA rule scanning (YARA-X)

Two tools scan **caller-held** local files or directories through a
caller-supplied [VirusTotal YARA-X](https://github.com/VirusTotal/yara-x) `yr`
binary. REA never installs YARA-X, fetches rules, or executes the scanned bytes.

| Tool                        | Rules source                                                 |
| --------------------------- | ------------------------------------------------------------ |
| `scan_artifact_with_rules`  | The caller's own rule file or rule directory (`rules_path`). |
| `scan_for_crypto_constants` | REA's bundled, hash-pinned crypto-constant pack.             |

## Configuration

| Setting             | Meaning                                                  |
| ------------------- | -------------------------------------------------------- |
| `REA_YARAX_COMMAND` | **Required.** Absolute path to the caller's `yr` binary. |

There is no `PATH` fallback. The provider asserts the client with
`yr --version` before every scan. Install YARA-X yourself (`cargo install
yara-x-cli` or a published release); REA does not run that command.

## Bundled crypto-constant pack

`third_party/yara-rules/crypto/` ships a curated pack of algorithm-specific
constant tables (AES S-boxes, SHA-256 round constants, MD5 state, CRC-32
polynomial, TEA delta, Blowfish P-array, Salsa20/ChaCha20 sigma, PKCS#1
DigestInfo prefixes, and the Base64 alphabet). `manifest.json` pins the pack's
SHA-256; the provider verifies it before every scan and refuses with
`capability_unavailable` when the file is missing or does not match. REA never
downloads a replacement pack.

Matches are **indicators, not proof**: compilers, table generators, and test
vectors can share the same bytes.

## What reaches Evidence

- target path, byte count, and SHA-256 (null when the target is a directory);
- the rule path and its SHA-256, plus the pack identity and version when REA's
  pack is used;
- each matching rule's name, namespace, tags, and matched field names with
  offsets and lengths;
- the client command and version, a truncation flag, and an unparsed count.

Matched bytes and rule metadata values never reach Evidence.

The exact YARA-X JSON fields this lane consumes are documented assumptions; no
YARA-X release is pinned yet, and every result carries that note.
