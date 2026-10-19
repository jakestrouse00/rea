# iOS device provider (pymobiledevice3)

The `idevice` provider reads iOS device facts through a **caller-supplied**
`pymobiledevice3` CLI on macOS. REA never installs pymobiledevice3, its Python
dependencies, iOS developer disk images, or anything else; it supervises the
launcher the caller selects and records device observations as Evidence.

> **Scope decision: approved by fork maintainer, 2026-10-19; boundaries as
> documented below.** Maintainer approval covers the read-only opset in this
> guide and nothing else: no app install or removal, no file push, no debug
> bridge mount, no profile install. The real-device lane was **not** exercised
> on the implementing host (no `pymobiledevice3` installed, no paired device),
> so no release is pinned as verified and every release reports unverified
> until a maintainer lane records one.

## Configuration

| Setting                   | Meaning                                                                        |
| ------------------------- | ------------------------------------------------------------------------------ |
| `REA_IPHONE_PMD3_COMMAND` | **Required.** Absolute path to the caller's `pymobiledevice3` launcher script. |
| `REA_IDEVICE_TIMEOUT_MS`  | Optional deadline for one one-shot device command (default 60000 ms).          |

The provider refuses plainly on non-macOS hosts; only the macOS lane was in
scope. Run `rea doctor --provider idevice` to probe the configured launcher.

## Boundary and discipline

- Owned provider processes: every command runs as a supervised child with
  bounded output (4 MiB) and a stop signal, following the shared process
  supervision primitives.
- Private staging: screenshots and crash pulls land in an REA-private runtime
  root and are published exactly once into `--output-directory` with a
  SHA-256. Staging roots that cannot be confirmed removed stay owned for
  close-time retry.
- Read-only opset: there is **no** install, removal, push, or debug-bridge
  mount operation at all. Not "not exposed by this provider" — absent from the
  opset by the scope decision above.
- Unpaired hosts are an **empty inventory**, not an error. A missing device or
  missing app is reported honestly as a partial observation.

## Operations

| Tool                       | CLI                        | Question it answers                                                     |
| -------------------------- | -------------------------- | ----------------------------------------------------------------------- |
| `list_ios_devices`         | `list-ios-devices`         | What is connected through usbmuxd, and is it paired?                    |
| `inspect_ios_device`       | `inspect-ios-device`       | Which model, iOS version, and connection type is this device?           |
| `read_ios_syslog`          | `read-ios-syslog`          | What did the device log during a bounded window (≤120 s)?               |
| `capture_ios_screenshot`   | `capture-ios-screenshot`   | What does the device screen show right now?                             |
| `list_ios_crash_reports`   | `list-ios-crash-reports`   | Which crash reports does the device retain?                             |
| `inspect_ios_crash`        | `inspect-ios-crash`        | What is in one retained crash report?                                   |
| `list_ios_apps`            | `list-ios-apps`            | Which apps are installed (bundle ids and reported metadata)?            |
| `inspect_ios_provisioning` | `inspect-ios-provisioning` | What provisioning/signing metadata does the launcher report for an app? |

Unrecognized launcher fields are preserved verbatim (`fields` /
`unparsed_lines`) instead of being guessed; unknown pairing, signer, and
provisioning facts remain unknown rather than absent.

## Honest limitations

- **CLI shapes are unverified.** The commands assume
  `pymobiledevice3 <group> <subcommand>` layout (`usbmux list`, `lockdown info
  -u`, `syslog --timeout`, `developer dvt screenshot <path>`, `crash list`,
  `crash copy --out`, `apps list -u`). The implementing host could not run the
  real launcher, so the argv tables are documented assumptions pending the
  maintainer's device lane.
- No release is pinned as verified (`IdeviceRelease.ts` keeps the verified
  constant `null`); a future maintainer lane must record one before any claim
  of verified behavior.
- Simulated-fixture tests (`tests/boundary/providers/idevice/`) cover provider
  and lifecycle behavior only; they do not establish real-device behavior.
