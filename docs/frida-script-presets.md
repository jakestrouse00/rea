# Frida script presets

`load_frida_script_preset` loads one named Frida agent into an existing
session, alongside the free-form `load_frida_script` tool. Presets exist so a
routine first step — continuing past certificate pinning, past jailbreak/root
detection, or reading the Android Keystore's structure — does not depend on a
caller authoring the same agent again.

## Presets in this release

| Preset                    | What it hooks                                                                                                                                          | Evidence reports                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------- |
| `ssl-unpinning`           | OkHttp `CertificatePinner`, conscrypt `TrustManagerImpl`, `X509TrustManagerExtensions`, the `NSURLSession` challenge delegate                          | the four addressed pinning methods    |
| `jail-root-detect-bypass` | `java.io.File.exists`, `java.lang.Runtime.exec`, `android.os.Build.TAGS`, `ApplicationPackageManager.getPackageInfo`, `NSFileManager.fileExistsAtPath` | the five addressed detection surfaces |
| `keystore-dump-structure` | `AndroidKeyStore` alias enumeration and each key's `getAlgorithm`/`getFormat`                                                                          | the alias-structure surfaces          |

Each preset is a **minimal reference agent authored for this repository**. It
hooks only the checks listed above and reports structure only: a hook name,
whether it resolved, a counter, or a key alias with its algorithm and format.
No certificate, key material, file content, property value, or payload byte is
sent, and no script text is returned or recorded.

An unlisted check in the target keeps working. A preset is a starting point for
observation, not a claim that every pinning or detection mechanism in the app
has been addressed.

## Licensing

The presets are part of REA's MIT-licensed source. Related upstream projects —
including the AGPL-3.0 `httptoolkit/frida-interception-and-unpinning` collection
and objection's own pinning scripts — are **not vendored and not reproduced**
here. `third_party/frida-presets/README.md` records the upstream references,
their licenses, and why no upstream text ships in this release.

## Evidence discipline

`load_frida_script_preset` returns:

- `preset` and `preset_title` — which agent loaded;
- `script_sha256` and `script_bytes` — the exact authored bytes that were
  loaded, identified by digest only;
- `detected_methods` — the preset's declared list of pinning or detection
  surfaces it addresses. This is a declaration, not an observation of what the
  target implements;
- `message_count` and `messages_truncated` — how much the target said during
  the load, without retaining the messages themselves in this Evidence.

The target's own hook-status rows (`{"event":"rea-preset",...}`) and bypass
counters (`{"event":"rea-preset-bypass",...}`) stay in the session message
stream, where `frida_session_status` reports them under the session's existing
capture limits. To read that stream, select the session's `scripts` entries
after the load.

## Requirements

- A Frida session already open through `start_frida_session`.
- The target runtime the preset needs: `Java.available` for the Android hooks,
  `ObjC.available` for the iOS hooks. A preset reports `unavailable` for a hook
  family the target does not have, in that family's own message row.
- The same authority as `load_frida_script`: loading a preset mutates target
  behavior, and `close_frida_session` remains the way to release it.

## What this does not do

- It does not install Frida server, gadget, or any platform tooling.
- It does not add pinning bypass to the mitmproxy lane; that lane's proxy trust
  stays caller-supplied.
- It does not verify the preset's effectiveness against a specific app. Verify
  on your own target, and treat an absence of bypass messages as an absence of
  the hooked call, never as proof the app is unaffected.
