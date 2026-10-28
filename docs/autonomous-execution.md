# Autonomous execution policy

REA can drive long-running work: build and test commands in a
[lab VM](./lab-vms.md), process captures on the host, and, in later releases,
fuzzing loops, protocol probes, and interception runs. This page is the policy
those lanes have to satisfy. It is written for the analyst deciding what a run
may touch, not for the tool implementation.

## Targets must be lab-owned

An autonomous loop may only execute code that the analyst already owns: a
target the analyst built, a target shipped as a public artifact, or a fixture
the analyst created. The following are never lab-owned, whatever the loop can
technically reach:

- a target taken from someone else's device or account;
- production endpoints, third-party services, or accounts the analyst does not
  operate;
- a copy of a target that is still live and in use elsewhere;
- data whose handling terms the analyst cannot state.

"Lab-owned" describes authority, not containment. Running an unowned target in
a VM, a container, or a sandbox is still unauthorized execution; the isolation
limits blast radius, it does not create permission.

## What a lab-owned scope looks like

A scope is a written enumeration, kept beside the run and reproduced in
Evidence. Record at minimum:

- the exact targets: absolute paths with SHA-256 digests, and the format the
  analyst believes they are;
- the network destinations the run may reach, by address and port, or an
  explicit statement that the loop is offline;
- the host or guest state the loop may write, named by directory;
- the time budget and the command budget;
- who owns the result and where it will be published.

Scope is part of the request, not part of the result: if the analyst has not
stated it, the run does not happen. A scope that grew during a run is a finding
to report, not a silent extension.

## Scopes recorded in Evidence

Every Evidence record carries the subject identity and the execution
environment, and autonomous lanes reuse both rather than inventing prose:

- **Subject.** `EvidenceSubjectTarget` is `{ path, sha256, format,
  architecture? }`: the artifact's absolute host path, its SHA-256, the format
  the reader validated, and an architecture only when one is known. A lane that
  produced its observation from a file it could not admit as a subject records
  `subject: null` with `subject_unavailable_reason`; it never substitutes a
  display path, a basename, or a hostname for the identity it did not observe.
- **Environment.** `environment.isolation` states the boundary the work ran
  under: `none`, `process`, `container`, or `virtual-machine`, together with the
  environment id, platform, and architecture. A lab-VM observation reports
  `virtual-machine`; a bare host command reports `process` or `none`.
- **Locations.** Produced and modified artifacts appear as `artifact-path`
  locations on the record, so the published scope is the list of paths the run
  actually touched.
- **Limitations.** Anything the lane could not observe stays in `limitations`:
  a bounded inventory, a guest-side effect that never touched the mount, a
  cleanup that remains owned, and — for any lane that proxies a guest — the fact
  that a failure message can carry a bounded excerpt of proxied guest output.

A scope recorded this way is comparable across runs and exportable, which is
what an audit needs. Prose in a commit message is not.

## Host sandbox profiles

`src/domain/sandboxProfiles.ts` renders the deny-default seatbelt (SBPL)
profile used for autonomous subprocess launches on macOS. Every profile starts
from `(deny default)` and admits only:

- the declared workspace writes, and any additional caller-declared writable
  directories;
- a fixed read-only baseline for the dynamic loader and shared libraries, plus
  caller-declared read paths;
- the exact executables the loop may spawn, by absolute path;
- the declared outbound destinations, by IP literal and port (hostnames are
  rejected: the kernel matches addresses, not names);
- explicitly named Mach services. The list is empty by default, so no service
  lookup is admitted without being written down.

Requests SBPL cannot represent — relative or `..` paths, control characters,
an empty executable allowlist, a hostname, an out-of-range port — are rejected
rather than widened.

`REA_DISABLE_SANDBOX` is the emergency exit. A disabling value (`1`, `true`,
`yes`, `on`) runs the launch without the profile and returns a fixed limitation
statement that must ride on the resulting Evidence, so an unconfined launch is
never reported as confined. An unrecognized value refuses the launch: REA does
not guess whether `maybe` meant "disable" or "keep". Use the exit only while
recovering from a profile defect, and say so in the run's notes.

## Escalation

- Widening a network allowlist, a writable directory, or an executable
  allowlist is a scope change: record why, and rerun rather than editing a
  profile mid-run.
- Reaching outside the lab (a real service, a shared account, a peer's device)
  ends the autonomous part of the work. Ask the owner.
- A capability that cannot state its subject, its isolation, or its cleanup
  owner is not ready to run autonomously, even if it is implemented.
