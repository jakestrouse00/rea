// REA reference Frida agent (MIT, authored for this repository).
//
// Minimal Android Keystore structure dump. It enumerates the aliases the
// AndroidKeyStore provider exposes and reports each entry's structural facts:
// the alias name and the reported key algorithm/format. Key material, encoded
// bytes, certificates, and challenge values are never read or sent.
//
// Emitted rows: {"event":"rea-keystore","alias":NAME,"algorithm":A,
//               "format":F,"entry_type":T} per alias and
//               {"event":"rea-keystore-summary","aliases":N,"error":E|null}.

const PRESET = "keystore-dump-structure";

function summarize(aliases, error) {
  send({ event: "rea-keystore-summary", preset: PRESET, aliases: aliases, error: error });
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
  summarize(0, "the target has no Java runtime");
} else {
  Java.perform(function () {
    try {
      const KeyStore = Java.use("java.security.KeyStore");
      const store = KeyStore.getInstance("AndroidKeyStore");
      store.load(null, null);
      const aliases = store.aliases();
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
      summarize(count, null);
    } catch (error) {
      summarize(0, String(error));
    }
  });
}
