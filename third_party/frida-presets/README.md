# Frida preset references

REA ships named Frida presets (`load_frida_script_preset`). The scripts in
`bridge/frida/presets/` are **authored for this repository** as minimal
reference agents over publicly documented checks. They are MIT-licensed with the
rest of REA.

## Upstream projects this lane refers to, and does not vendor

| Project | License | Relationship |
| --- | --- | --- |
| [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) | AGPL-3.0 | Referenced by name only. No file, excerpt, or derived text from that project is present in this repository or its npm package. Its certificate-pinning coverage on Android and iOS informed which checks the `ssl-unpinning` reference agent hooks. |
| [objection](https://github.com/sensepost/objection) | GPL-3.0 | Referenced by name only. REA runs a caller-installed objection as a subprocess (`run_objection_recipe`) and never links, bundles, or patches it. |
| [Frida](https://frida.re) | LGPL-2.0 WITH WxWindows-exception-3.1 | REA's transport is the `frida` Node binding recorded in [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md); no Frida server, gadget, or platform tooling is bundled. |

Why the AGPL project is not vendored: distributing its JavaScript inside REA's
MIT package would either relicense the combined work or make REA's distribution
AGPL-obligated, and the presets only need the *shape* of the checks. A short
agent that hooks the documented classes and methods is enough for a first
observation, and it keeps the license story in this repository simple.

## Adding a preset

1. Add `bridge/frida/presets/<name>.js` — structure-only rows, one
   `{"event":"rea-preset",...}` per hook, no payload values.
2. Declare it in `src/frida/FridaScriptPresets.ts` with its `detectedMethods`
   list and `fileName`; the caller-visible name is the enum in
   `src/domain/fridaScriptPreset.ts`.
3. Extend the license table above if any upstream project informed the new
   agent, and say plainly whether text was copied (it must not be).
4. Add `bridge/frida/presets` to `package.json#files` so the agent ships with
   the package, then run the preset regressions.
