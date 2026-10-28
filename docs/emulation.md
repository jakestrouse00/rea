# Isolated emulation

Answer "what does this code do when it runs?" for one function body without
running it natively, and "what bytes would this patch assemble to?" — through
REA's own Unicorn/Keystone sidecar.

MCP registers two tools for this lane:

| Tool                        | Question it answers                                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `emulate_function_isolated` | What registers, memory windows, executed addresses, and call counts did one bounded execution of these bytes produce? |
| `assemble_bytes`            | What exact bytes does this assembly encode to for this architecture?                                                  |

REA does not register a disassembler here: `execute_rizin_command` and
`inspect_with_objdump` already answer disassembly, and a second decoder would be
a second interpretation of the same bytes.

## What the lane is, and is not

Each request runs **one** job: a fresh sidecar process is spawned, the job is
answered, and the process is stopped. There is no session object, no target that
stays loaded, and no availability-policy entry to acquire or release.

The code under analysis runs only inside Unicorn's CPU and memory model:

- No instruction executes natively on the host, and REA never injects into or
  resumes a live process.
- No operating system, loader, import, or syscall is modelled. A call into an
  unmapped address ends the job with `invalid_memory_access` instead of being
  satisfied by a stub.
- Nothing is written to the selected artifact. The sidecar runs with `-I -B`, so
  it neither reads `PYTHON*` variables nor writes bytecode caches beside your
  files.
- Emulation is deterministic: the same request against the same bytes produces
  the same result.

## Setup

The sidecar is REA-owned source; Unicorn and Keystone are bring-your-own. REA
never creates the Python environment, never installs a wheel, and never upgrades
it.

1. Create an environment with the pinned engine releases:

   ```sh
   python3 -m venv ~/.local/share/rea-unicorn
   ~/.local/share/rea-unicorn/bin/pip install 'unicorn>=2.1,<2.2' keystone-engine
   ```

2. Point REA at that interpreter and at this repository's bridge directory, then
   restart REA:

   ```sh
   export REA_UNICORN_PYTHON="$HOME/.local/share/rea-unicorn/bin/python"
   export REA_UNICORN_BRIDGE_DIR="$PWD/bridge/unicorn"
   ```

Both settings are fail-closed. If either is unset, relative, missing, or not
executable, the tools refuse with a `capability_unavailable` result that names
the setting and its remediation; nothing is spawned and no partial result is
reported. `binary_session` reports the same selection through
`emuEmulationEnabled`, so a misconfigured host is visible before the first call.

### Version pinning

The bridge is written against **Unicorn 2.1.x** and refuses to run on any other
minor release (`version_unsupported`). It reports the exact `unicorn` and
`keystone` versions it loaded in every result, so a recorded observation always
names the engine that produced it. Keystone is imported lazily: an
`emulate_function_isolated` job works without it, and `assemble_bytes` refuses
with `missing_dependency` when it is absent. Assembly needs no Unicorn at all, so
an environment with Keystone but no Unicorn answers `assemble_bytes` and reports
`unicorn_version: null` in the job identity.

### Wire protocol

One JSON request line on stdin, one JSON answer line on stdout, diagnostics on
stderr, protocol `1`:

```json
{"protocol":1,"job_id":"<uuid>","kind":"emulate","arch":"x86_64","code_hex":"4889f8c3","code_base":"0x401000","entry":"0x401000","stack_size":65536,"args":[],"max_steps":100000,"timeout_ms":10000,"stop_addresses":[],"observe_registers":["rax"],"observe_memory":[],"limits":{"max_edges":4096,"max_call_targets":32}}
{"protocol":1,"job_id":"<uuid>","kind":"emulate","ok":true,"result":{...}}
```

A frame that is not one JSON line, exceeds the frame budget, or does not match
the declared contract is a typed protocol refusal; it is never partially
accepted. The request and answer budgets are fixed at 1 MiB per line.

## Bounds

| Bound                   | Value                                                                        | Setting                  |
| ----------------------- | ---------------------------------------------------------------------------- | ------------------------ |
| Executed instructions   | `max_steps`, default 100 000, at most 5 000 000                              | `emu.max_steps`          |
| Wall time               | `timeout_ms`, default 10 000 ms, at most 30 000 ms, plus 2 000 ms stop grace | `emu.timeout`            |
| Code admitted           | 256 KiB from a file slice or hex literal                                     | `emu.code_bytes`         |
| Stack region            | `stack_size`, default 64 KiB, at most 1 MiB                                  | `emu.stack_bytes`        |
| Observed memory windows | 32 windows of at most 64 KiB                                                 | `emu.memory_windows`     |
| Executed edges retained | 4 096 distinct address pairs                                                 | `emu.executed_edges`     |
| Call targets retained   | 32 distinct addresses                                                        | `emu.call_targets`       |
| Assembled bytes         | 64 KiB per request                                                           | `emu.assembled_bytes`    |
| Bridge frame            | 1 MiB per line                                                               | `emu.bridge_frame_bytes` |

Exceeding a step or time bound is a completed job whose `coverage` is `partial`
and whose `exit` names the bound. Every bound above is a published, fixed
control: `inspect_analysis_settings` reports the same names and values, and none
of them has a runtime override. Exceeding a storage bound keeps the job and
marks `edges_truncated` or `call_targets_truncated`, so an omitted edge is never
reported as absence of an edge.

## Evidence discipline

`emulate_function_isolated` returns:

- `code`: the source kind, path, offset, length, and SHA-256 of exactly the bytes
  REA selected — the bridge must echo that digest, and a mismatch is a protocol
  refusal.
- `registers`: typed values (`0x`-prefixed, bounded width) for the registers the
  caller named, plus `unknown_registers` for names this architecture mode has no
  value for.
- `memory`: for each requested window, its address, length, and SHA-256. Bytes
  are never returned, and unreadable windows are counted in `memory_omitted`.
- `edges`: executed address pairs such as `0x401000->0x401004`, in first-seen
  order, with the total retained count.
- `call_count` and bounded per-target counts, derived from executed call opcodes.
- `executed_steps`, `exit`, and `exit_detail`.

Code bytes and stub argument values never appear in Evidence. Emulated memory
content never appears in Evidence.

`assemble_bytes` returns the exact bytes the caller asked Keystone to encode,
because producing those bytes is the request; it also records the assembly source
the caller supplied, the base address, the size, and the SHA-256.

## Architecture modes

`x86_16`, `x86_32`, `x86_64`, `arm`, `thumb`, `arm64`, `mips32`, `mips64`, and
`ppc32`. Big-endian emulation is available only for `arm`, `mips32`, `mips64`,
and `ppc32`; any other architecture with `endianness: "big"` is refused before a
process starts.

The code, stack, and sentinel regions all have to fit the mode's address space,
so a 16-bit mode with the default `code_base` is refused before a process
starts: select a `code_base` and `stack_size` that fit the mode.

Stub arguments are placed by the architecture calling convention: `rdi`/`rsi`/
`rdx`/`rcx`/`r8`/`r9` for x86-64, the stack for x86-16/x86-32, `r0`–`r3` for
ARM and Thumb, `x0`–`x7` for AArch64, `a0`–`a3` for MIPS, and `r3`–`r10` for
PowerPC. Arguments beyond those registers are pushed first, so the entry stack
reads `[sp] = return address`, `[sp + word] = first stack argument`, and so on —
the layout a caller's `call` would have produced.

The return address is a REA-owned sentinel page mapped beyond the stack, and how
it is delivered depends on the architecture:

- **`x86_16`, `x86_32`, `x86_64`** — the sentinel is pushed as the top word of
  the private stack at entry, so the function's own `ret` pops it. `rsp`/`esp`/`sp`
  therefore already point at the return address when the first instruction runs,
  and any stack argument sits above it. A function that returns normally ends as
  `exit: "returned"`.
- **`arm`, `thumb`, `arm64`, `mips32`, `mips64`, `ppc32`** — the sentinel goes
  into the link register (`lr`, `x30`, `ra`, `lr`) and the stack pointer stays at
  the top of the stack region. Here a `return` branches to the link register
  rather than popping memory, so the stack is untouched by the return.

Both mechanisms end at the same sentinel address, which Unicorn stops on before
fetching anything there; the mapped page holds no meaningful instructions. The
difference matters when reading the job's final registers: on x86 the entry stack
pointer sits one word below the pre-call stack top and `sp` advances past the
return address as it pops, while on link-register architectures `sp` is unchanged
by the return.

## Limitations

- One execution path per call. There is no exploration of alternate branches; run
  the job again with different arguments or stop addresses to reach another path.
- No OS semantics. Blocking APIs, thread creation, file I/O, and dynamic linking
  are outside the model, so a function that depends on them stops early.
- Call counts identify call opcodes, not symbols or argument values.
- Executed edges are observed address pairs at instruction boundaries, not a
  decoded basic-block graph; pair them with a real disassembler when you need
  decoded instructions.
- Self-modifying code and memory the job never touches are not observed. Only the
  windows you ask for are hashed.
- `inspectAvailability` reports the configured selection; it does not import
  Unicorn. A missing or mismatched engine surfaces on the first job as
  `capability_unavailable` with a bounded stderr excerpt.

## Why Unicorn rather than p-code lifting

[Non-goals](non-goals.md#full-binary-lifting-stacks-remill-anvill-mcsema) records
that REA declined full binary-lifting stacks. The emulation lane takes the other
half of that decision: a small, pinned interpreter with real CPU semantics is
enough to answer "what did this code change?" without an LLVM-pinning build and
without depending on a GUI provider's p-code cache. P-code emulation through
Ghidra remains a possible later lane; it is no longer a planned prototype.

## Offline verification

The lane's boundary tests run against a scripted fake sidecar: a fixture process
that reads one request line and writes one answer line. They cover the file-slice
and hex sources, code-identity mismatch, frame and JSON refusal, the deadline,
cooperative cancellation, a pre-cancelled caller, bridge refusals, an exited
sidecar, and every configuration refusal. No real Unicorn, Keystone, native
target, or host execution is exercised by those tests, so they establish REA's
own framing and bounds, not engine behavior.
