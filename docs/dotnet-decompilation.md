# .NET decompilation (ilspycmd)

`decompile_dotnet_assembly` reports one **caller-held** .NET assembly's
declaration structure through a caller-supplied
[ilspycmd](https://github.com/icsharpcode/ILSpy/tree/master/ICSharpCode.ILSpyCmd)
binary. REA never installs ilspycmd and never runs the assembly.

## Configuration

| Setting              | Meaning                                                            |
| -------------------- | ------------------------------------------------------------------ |
| `REA_ILSPY_CMD_PATH` | **Required.** Absolute path to the caller's `ilspycmd` executable. |

This lane formalizes the setting REA already reported through its doctor
checks; it adds no second variable. An unset or relative value is a typed
configuration refusal naming the setting and remediation. The provider asserts
the client with `ilspycmd --version` before every operation.

Install ilspycmd yourself, for example with
`dotnet tool install -g ilspycmd`; REA does not run that command.

## What reaches Evidence

The result reports the assembly path, size, SHA-256, derived assembly name, and
for each type its namespace, name, kind, base type, and bounded member
signatures. A covered/unparsed line count makes partial parses visible.

Decompiled C# text never reaches Evidence. The declaration scanner is shallow:
nested scopes, attributes, and compiler-generated members can be
under-reported, and an absent member is not proof that it is absent.

The ilspycmd output shape is a documented assumption; no ilspycmd release is
pinned yet, and every result carries that note.
