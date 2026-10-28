// REA reference Frida agent (MIT, authored for this repository).
//
// Minimal Android Keystore structure dump. It enumerates the aliases the
// AndroidKeyStore provider exposes and reports each entry's structural facts:
// the alias name and the reported key algorithm/format. Key material, encoded
// bytes, certificates, and challenge values are never read or sent.
//
// Emitted rows: {"event":"rea-preset","hook":API,"status":...,"detail":...}
// for each Keystore API the dump used, {"event":"rea-keystore",...} per alias,
// and {"event":"rea-keystore-summary","aliases":N,"error":E|null}.
//
// This preset hooks nothing: it is a one-shot structure read, and the APIs
// listed below are the ones it calls.

const PRESET = "keystore-dump-structure";

// The Keystore structure APIs this agent uses; the preset's declared
// detected_methods are exactly these names so the shipped code backs the claim.
const STRUCTURE_APIS = [
  "java.security.KeyStore.getInstance",
  "java.security.KeyStore.aliases",
  "java.security.Key.getAlgorithm",
  "java.security.Key.getFormat",
];

function summarize(aliases, error) {
  send({ event: "rea-keystore-summary", preset: PRESET, aliases: aliases, error: error });
}

function reportApi(api, status, detail) {
  send({ event: "rea-preset", preset: PRESET, hook: api, status: status, detail: detail });
}

function entryTypeOf(store, alias) {
  try {
    if (store.isKeyEntry(alias)) return "key";
    if (store.isCertificateEntry(alias)) return "certificate";
    return "unknown";
  } catch (error) {
    return "unknown";
  }
}

function algorithmOf(store, alias) {
  try {
    const key = store.getKey(alias, null);
    if (key === null) return null;
    return key.getAlgorithm();
  } catch (error) {
    return null;
  }
}

function formatOf(store, alias) {
  try {
    const key = store.getKey(alias, null);
    if (key === null) return null;
    return key.getFormat();
  } catch (error) {
    return null;
  }
}

if (!Java.available) {
  for (const api of STRUCTURE_APIS) reportApi(api, "unavailable", "the target has no Java runtime");
  summarize(0, "the target has no Java runtime");
} else {
  Java.perform(function () {
    try {
      const KeyStore = Java.use("java.security.KeyStore");
      const store = KeyStore.getInstance("AndroidKeyStore");
      reportApi(STRUCTURE_APIS[0], "installed", "AndroidKeyStore provider opened");
      store.load(null, null);
      const aliases = store.aliases();
      reportApi(STRUCTURE_APIS[1], "installed", "alias enumeration");
      let count = 0;
      while (aliases.hasMoreElements()) {
        const alias = aliases.nextElement().toString();
        send({
          event: "rea-keystore",
          preset: PRESET,
          alias: alias,
          algorithm: algorithmOf(store, alias),
          format: formatOf(store, alias),
          entry_type: entryTypeOf(store, alias),
        });
        count += 1;
      }
      reportApi(STRUCTURE_APIS[2], "installed", "per-alias key algorithm reported");
      reportApi(STRUCTURE_APIS[3], "installed", "per-alias key format reported");
      summarize(count, null);
    } catch (error) {
      for (const api of STRUCTURE_APIS) reportApi(api, "failed", String(error));
      summarize(0, String(error));
    }
  });
}
