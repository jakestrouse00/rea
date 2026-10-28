# Lab VMs

`start_lab_vm`, `run_lab_vm_command`, and `stop_lab_vm` manage one ephemeral
Linux virtual machine on an Apple silicon macOS host through a caller-supplied
[Lima](https://lima-vm.io/) installation. The lane exists for work that cannot
run on the host directly: AFL++ and ASan builds, sanitizer-heavy test suites,
distribution-specific toolchains, and containerized benchmarks.

The same three tools are session tools on the MCP server only; this release has
no CLI command for them. Each tool returns Evidence, and the lane never reports
a guest result as if it had run on the host.

| Setting               | Meaning                                                                                                                                                                                           |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REA_LIMACTL_COMMAND` | **Required.** Absolute path to a caller-supplied `limactl` binary. Fail-closed: a relative, missing, or non-executable path is a configuration refusal with the selected setting and remediation. |
| `REA_DISABLE_SANDBOX` | Emergency exit for deny-default host sandbox profiles. It does not change this lane; see [autonomous execution](./autonomous-execution.md).                                                       |

REA never downloads, installs, or upgrades Lima, and it does not ship a guest
image. A first boot therefore needs whatever image the generated template
references, plus the network access that pull requires. On a host without Apple
Virtualization.framework (`vz`), the lane reports `unsupported_host` instead of
falling back to another driver.

## Lifecycle

```text
start_lab_vm {"workspace_path":"/absolute/workdir"}
run_lab_vm_command {"session_id":"…","command":"cmake --build build","command_timeout_ms":600000}
stop_lab_vm {"session_id":"…"}
```

1. `start_lab_vm` validates the absolute workspace directory, writes one
   private template (mode `0600`, inside a private runtime root) that selects
   `vmType: vz` with Rosetta translation and mounts only that workspace
   read-write at `/workspace`, then runs `limactl start --tty=false --name <vm> <template>`.
   The `session_id` is issued only after that call observed a clean exit. A
   clean exit means the start command returned; it does not prove that every
   guest startup script finished.
2. `run_lab_vm_command` passes the command line to `/bin/sh -lc` inside the
   guest with `/workspace` as the working directory. The line travels as one
   argv element, so it is limited to 131072 UTF-8 bytes; longer work belongs in a
   script inside the workspace. Successful observations publish no guest output
   bytes: Evidence keeps the exit type, exit code, duration, stdout and stderr
   byte counts, truncation, and the workspace paths the command produced,
   modified, or removed. Those paths come from a bounded inventory taken
   immediately before and after the command, so a change that never touches the
   mount is not observed. The exit type distinguishes `exited`, `signalled`,
   `timeout`, cancellation, `output_truncated` (the retained-output budget
   stopped the process), and `not_started` (no process existed, so the launch
   failed rather than the guest).
3. `stop_lab_vm` runs `limactl stop` and then `limactl delete --force`, and
   releases the session identity only after both were observed. The mounted
   workspace is left untouched, so artifacts the guest wrote there remain on
   the host. A failed stop or removal keeps the identity retained and admits
   no further guest command. Calling `stop_lab_vm` again retries that owner:
   each removal step is recorded once observed, so a retry re-runs only the
   steps that are still unproven, and an instance that is already gone is
   confirmed through `limactl list --json` rather than by repeating a delete
   that cannot succeed. Concurrent retries of one identity are serialized, so
   only one of them can run a removal step. A retry that only observes removal
   reports `stop: null` instead of inventing a second stop call.

One REA server owns at most one lab VM at a time. That is a capacity bound, not
a claim that a second VM would not fit: each VM is a complete guest operating
system, and the bound keeps cleanup attribution unambiguous. `binary_session`
reports the lane's availability from the owner's own observation, including the
`unsupported_host` case and the selected `limactl` path.

## Observation boundaries

- Exit facts are observed; guest-side behavior inside the command is not. A
  zero exit status establishes the command's own report, not the correctness of
  what it built.
- `produced_paths`, `modified_paths`, and `removed_paths` compare two bounded
  inventories of the mounted workspace's regular files. Directories are
  descended into; symbolic links, sockets, FIFOs and device nodes are neither
  traversed nor reported, so a command that only creates or removes a link is
  not reported. `changes_truncated` marks a bounded inventory or change list
  that stopped before covering the workspace.
- Successful observations carry no guest output. A **failure** message can
  include up to 512 bytes of the `limactl` stderr tail, and `limactl shell`
  proxies guest output through that stream, so a bounded guest excerpt can
  reach an error reply. Evidence states this in its limitations; the excerpt is
  never part of a successful result.
- A timeout stops the owned `limactl` invocation at its deadline. It does not
  prove that a command it had already handed to the guest stopped running in
  the VM. `stop_lab_vm` removes the instance, which is what ends guest work.
- Cancellation keeps the caller's exact reason. Cancellation after `stop` was
  observed still reports the typed cancellation, with the retained cleanup
  owner attached, so a later retry can release it.
- `limactl` itself runs on this host without a deny-default seatbelt profile. VM
  management needs its own control socket, guest transport, and `~/.lima`
  state, and a deny-default profile would break it. Isolation for the work
  inside the guest comes from the virtual machine.

## Limits

| Bound                                         | Value                            | Override             |
| --------------------------------------------- | -------------------------------- | -------------------- |
| Live lab VMs per REA server                   | 1                                | None in this release |
| First boot (`limactl start`) deadline         | 900000 ms                        | None in this release |
| Guest command deadline (`command_timeout_ms`) | 120000 ms default, 1..2147483647 | Per call             |
| Guest command line                            | 131072 UTF-8 bytes               | None in this release |
| Failure-message stderr excerpt                | 512 bytes                        | None in this release |
| Retained `limactl` output per stream          | 4194304 bytes                    | None in this release |
| Workspace inventory entries                   | 20000                            | None in this release |
| Retained produced/modified/removed paths      | 512                              | None in this release |

## Verification status

The automated tests use a scripted `limactl` stand-in: it records argv, writes
into the mounted workspace, keeps instance state for `limactl list --json`, and
returns scripted exit statuses. They are offline and require no Lima
installation.

The absence confirmation assumes `limactl list --json` prints one JSON object
per instance with a `name` field, and that `start`, `shell`, `stop`, and
`delete --force` accept the argv this lane builds. The suite does not verify
those assumptions against a real Lima build, and it does not establish real
`vz` behavior, Rosetta translation, guest-image acquisition, or real guest
teardown. An unreadable instance list leaves absence unproven, so the retry
keeps the identity rather than releasing it.

See [autonomous execution](./autonomous-execution.md) before pointing this lane
at anything other than a lab-owned target.
