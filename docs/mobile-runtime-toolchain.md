# Mobile runtime and forensic toolchain

Three caller-supplied tools extend REA's mobile work past static structure:
`objection` for an attached app's runtime inventory, `androguard` for APK
structure and structure-rule findings, and `iLEAPP`/`ALEAPP` for a forensic
report's TSV tables. Each is a subprocess over a launcher the caller installs;
REA never installs, upgrades, links, or drives any of them over the network.

| Tool            | Setting                                                                                                   | Operations                                          |
| --------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| objection       | `REA_OBJECTION_COMMAND` (absolute path)                                                                   | `run_objection_recipe`                              |
| androguard 5.x  | `REA_ANDROGUARD_PYTHON` (absolute path to a Python that imports it), optional `REA_ANDROGUARD_BRIDGE_DIR` | `analyze_apk_structure`, `scan_apk_vulnerabilities` |
| iLEAPP / ALEAPP | `REA_ILEAPP_COMMAND` (absolute path)                                                                      | `run_mobile_forensics_report`                       |

Each tool reports its own readiness: `binary_session` shows one availability
row per lane, and an unconfigured lane refuses only its own tools.

## objection recipes

`run_objection_recipe` runs one whitelisted, read-only inventory recipe against
a caller-named target:

| Recipe                  | objection command path                | Rows                                           |
| ----------------------- | ------------------------------------- | ---------------------------------------------- |
| `app-environment-names` | `run env`                             | environment **key names** only; values dropped |
| `list-loaded-classes`   | `run android hooking list classes`    | loaded class names                             |
| `list-activities`       | `run android hooking list activities` | activity class names                           |
| `keystore-aliases`      | `run android keystore list`           | keystore alias names                           |

Free-form objection commands are not assembled from caller input, and no
recipe changes device or app state. The target selector is `-g <bundle>` or
`-n <process>`, plus an optional `-S <serial>`.

The tool's printed text is reduced to structural rows and counters at REA's
boundary: banner lines are counted as dropped, unrecognized lines are counted as
unparsed, duplicate rows collapse, and values never reach Evidence. Attaching
objection does change the app's debugger and instrumentation state, which is why
the tool is marked destructive.

objection is GPL-3.0. REA runs it as a subprocess only; its code is not part of
REA's dependency tree or package.

## androguard APK structure

`analyze_apk_structure` runs REA's bundled bridge
(`bridge/mobile/androguard_bridge.py`) with the caller's interpreter and reports:

- package identity, app name, version, min/target SDK;
- declared permissions and native libraries;
- declared activities, services, receivers, and providers with their `exported`
  flag (`null` when the manifest could not be read, never a guess);
- a bounded class-to-class cross-reference sample with per-pair counts.

The flag is the explicit `android:exported` attribute, or — before API 31, as the
platform itself infers it — the presence of an intent filter.

`scan_apk_vulnerabilities` evaluates this release's fixed structure rules and
reports each finding as `{id, severity, location}`:

| Rule id                                 | Severity | Observed at                                 |
| --------------------------------------- | -------- | ------------------------------------------- |
| `exported-component-without-permission` | warning  | the component                               |
| `debuggable-application`                | high     | `manifest:application@debuggable`           |
| `allow-backup-enabled`                  | warning  | `manifest:application@allowBackup`          |
| `cleartext-traffic-permitted`           | warning  | `manifest:application@usesCleartextTraffic` |
| `outdated-target-sdk`                   | info     | `manifest:uses-sdk@targetSdkVersion`        |
| `unknown-target-sdk`                    | info     | `manifest:uses-sdk@targetSdkVersion`        |
| `no-declared-permissions`               | info     | `manifest:uses-permission`                  |

Findings carry no matched value, rule text, or exploit path. This is a structure
review over declared facts, not a penetration test, and an unlisted rule is not
proof that a weakness is absent.

REA reads and digests the APK itself before the bridge runs; both tools report
that digest and byte count so a finding set is bound to one artifact identity.

## iLEAPP/ALEAPP reports

`run_mobile_forensics_report` runs the selected launcher as
`<command> -t <ios|android> -i <input_path> -o <output_directory>` and then
parses the `.tsv` tables it wrote:

- tables are listed deterministically, bounded by `max_tables`;
- each table keeps its header columns, up to `max_rows_per_table` rows, its
  SHA-256, and its byte count;
- cells are kept as written up to a per-cell bound; a truncated cell marks the
  table partial;
- a table REA refuses to read (unreadable, not a regular file, over the
  per-table byte bound) is named in `unparsed_files` rather than silently
  omitted.

The output directory is **caller-owned**: REA never creates, replaces, or
deletes it, so tables from an earlier run can be present and are reported as
read. The tool decides which artifacts it recognizes, so an absent table is not
evidence that an artifact was absent. Pair this lane with REA's own backup and
import steps to acquire the evidence; this lane never acquires it.

## Fixed bounds

| Bound                      | Value          | Effect                                            |
| -------------------------- | -------------- | ------------------------------------------------- |
| objection stdout capture   | 4 MiB          | a larger capture is refused, not partially parsed |
| androguard bridge stdout   | 16 MiB         | same                                              |
| per forensic table         | 8 MiB          | larger tables are reported as unparsed            |
| forensic tables per report | 32 MiB total   | later tables are counted as omitted               |
| forensic cell              | 512 characters | truncated cells mark the table partial            |

One androguard run has a fixed 300 s deadline; objection and the forensics
launcher take a per-call `timeout_ms`. None of these bounds has a runtime
override in this release.

## Limitations

- These tools' own parsing decides what is reported; REA bounds and normalizes
  their structure and does not independently verify their claims.
- Every lane is offline with respect to package installation: bring your own
  launchers and interpreter.
- Real-tool verification is out of scope for this release's tests, which use
  scripted child runs and fixture TSV tables. No claim is made here about a
  specific objection, androguard, or iLEAPP release's exact text output.
