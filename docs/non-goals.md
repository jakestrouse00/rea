# Non-goals

Recorded engine/platform capabilities that were evaluated and deliberately **not** pursued,
with the rationale at the time of evaluation (2026-10-19, fork-maintainer decision). Each
entry lists the evidence that was checked, so later re-evaluation can verify whether the
underlying constraint still holds. Being listed here is not a permanent veto: if a
constraint changes, re-evaluate; a scope expansion still needs the usual
[maintainer scope decision](CONTRIBUTING.md#contribution-scope).

## Platform capabilities declined

### DTrace on macOS

Apple's shipped probe set has collapsed across macOS releases (from ~350k probes to ~13k;
no default syscall probes on Apple Silicon; `dtruss` is unusable even with
`csrutil enable --without dtrace`). macOS-native live tracing is reached through
`xctrace`/Instruments instead, if that lane is ever pursued. Evidence: platform docs and
published measurements; no local lane exists.

### eBPF / bpftrace

Linux-only kernel technology; no macOS or Windows kernel support. REA's macOS host lane
cannot use it, and adding a Linux-host requirement for an observational tracer duplicates
the provider-side ADB/GDB lanes. Sources: bpftrace platform support matrix.

### Apple Endpoint Security framework

Requires the Apple-granted `com.apple.developer.endpoint-security.client` entitlement plus a
System Extension — an application-review process incompatible with a local,
bring-your-own-engine tool. Same practical wall applies to undocumented Kperf/libTraceKperf
direct use; reachable only through Apple's own `xctrace`.

### Volatility 3 for macOS memory images

macOS plugin support is officially deprecated upstream and acquisition (`osxpmem`) fights
SIP. Windows/Linux image analysis by Volatility is fine as a caller-side workflow but is not
a REA provider target. Live process memory inspection on macOS belongs to the debugger
plane (lldb/GDB/Frida), not image-forensics tooling.

### MemProcFS

Values are primarily for offline Windows dumps; requires FUSE on macOS. Does not fit the
host lane (macOS-first) and overlaps the crash/dump decoding already covered by the
pwntools/pwndbg offline lanes.

### Full binary-lifting stacks (remill / anvill / mcsema)

Actively maintained upstream but build is archaeologically painful (LLVM version pinning
dominates the dependency graph). Ghidra's p-code already provides the semantics
representation REA consumes; direct lifting adds an extra fragile toolchain for marginal
coverage gain.

Decision (2026-10-28, this fork): the semantics half is answered by the
[isolated emulation lane](emulation.md), which runs one function body inside a pinned
Unicorn 2.1.x CPU and memory model instead of lifting it. The earlier "p-code-based
emulation planned prototype" note is closed by that choice: a small bring-your-own
interpreter with real CPU semantics covers "what did this code change?" without
LLVM pinning and without depending on a provider's p-code cache. P-code emulation through
Ghidra is no longer planned; it may be re-proposed as its own lane if Unicorn's
unmapped-memory model proves insufficient for an analyst question that needs mapped
provider semantics.

## Fork decision on upstream category exclusions

The upstream project categorically excludes certain capability classes regardless
of their usefulness. This fork's maintainer removed those category exclusions on
2026-10-19 (recorded in [CONTRIBUTING.md](CONTRIBUTING.md#contribution-scope)):
packer/virtualization handling, anti-debug/anti-instrumentation workflows,
protection bypass, and exploit/attack automation are not categorically
excluded here. Capabilities in those areas are still governed by the
fail-closed integration rule — execution and mutation authority, side-effect
review, and verification — and by the legal responsibility clause in
CONTRIBUTING.md (contributors' rights and authorization for their work).
