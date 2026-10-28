# Python source recovery (PyLingual / pycdc)

`decompile_python_bytecode` recovers the declaration shape of one **caller-held**
`.pyc` or bytecode archive through a caller-supplied PyLingual or pycdc binary.
REA never installs a decompiler and never invokes CPython on the artifact.

## Configuration

| Setting                 | Meaning                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| `REA_PYLINGUAL_COMMAND` | Absolute path to a PyLingual CLI. Tried first when both are set. |
| `REA_PYCDC_COMMAND`     | Absolute path to a pycdc executable.                             |

At least one is required. An unset pair is a typed configuration refusal that
names both settings and the remediation. Both selections must be absolute and
executable.

## What reaches Evidence

The result reports the bytecode path, size, SHA-256, each function's name,
qualified name, line range, and parameter count, plus class names, import module
names, and counts. A covered/unparsed line count makes partial parses visible.

Recovered Python source never reaches Evidence. Decompiler output is not
guaranteed to be valid, complete, or faithful to the original source; a
decompiler failure is reported as a protocol error rather than a partial
success.

The PyLingual and pycdc output shapes are documented assumptions; no verified
release of either tool is pinned yet, and every result carries that note.
