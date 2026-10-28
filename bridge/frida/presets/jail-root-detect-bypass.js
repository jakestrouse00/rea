// REA reference Frida agent (MIT, authored for this repository).
//
// Minimal jailbreak/root-detection visibility-and-bypass preset. It hooks the
// path, property, and package checks that public writeups describe, so a
// caller can see which detection surfaces the target uses and keep the
// session running. Structure only: a hook name, its resolution status, and a
// call counter. No file content, property value, or package list is emitted.
//
// Emitted rows: {"event":"rea-preset","preset":"jail-root-detect-bypass",...},
// {"event":"rea-preset-bypass","hook":NAME,"count":N} per refused probe, and
// {"event":"rea-preset-omission","hook":NAME,"count":N,"reason":...} when a
// probe could not be read as a path at all.

const PRESET = "jail-root-detect-bypass";

function report(hook, status, detail) {
  send({ event: "rea-preset", preset: PRESET, hook: hook, status: status, detail: detail });
}

function counter(hook) {
  let count = 0;
  return function () {
    count += 1;
    send({ event: "rea-preset-bypass", preset: PRESET, hook: hook, count: count });
  };
}

// A check the hook could not evaluate is reported, never silently passed
// through: an installed hook that observes nothing must say so.
function omission(hook, reason) {
  let count = 0;
  return function () {
    count += 1;
    send({ event: "rea-preset-omission", preset: PRESET, hook: hook, count: count, reason: reason });
  };
}

const ROOT_PATH_MARKERS = [
  "/system/app/Superuser.apk",
  "/system/xbin/su",
  "/sbin/su",
  "/data/local/bin/su",
  "/data/local/xbin/su",
  "/system/bin/failsafe/su",
  "/su/bin/su",
];

const JAILBREAK_PATH_MARKERS = [
  "/Applications/Cydia.app",
  "/Library/MobileSubstrate/MobileSubstrate.dylib",
  "/bin/bash",
  "/usr/sbin/sshd",
  "/etc/apt",
  "/private/var/lib/apt/",
  "/private/var/lib/cydia",
  "/usr/libexec/cydia/firmware.sh",
  "/private/var/stash",
  "/var/jb",
];

const matches = function (text) {
  if (typeof text !== "string") return false;
  for (const marker of ROOT_PATH_MARKERS) if (text.indexOf(marker) !== -1) return true;
  for (const marker of JAILBREAK_PATH_MARKERS) if (text.indexOf(marker) !== -1) return true;
  return false;
};

function hookJava() {
  try {
    const File = Java.use("java.io.File");
    const bump = counter("java.io.File.exists");
    File.exists.implementation = function () {
      const path = this.getAbsolutePath();
      if (matches(path)) {
        bump();
        return false;
      }
      return this.exists();
    };
    report("java.io.File.exists", "installed", "root path markers report absent");
  } catch (error) {
    report("java.io.File.exists", "unavailable", String(error));
  }

  try {
    const Runtime = Java.use("java.lang.Runtime");
    const bump = counter("java.lang.Runtime.exec");
    Runtime.exec.overload("java.lang.String").implementation = function (command) {
      if (matches(command)) {
        bump();
        report("java.lang.Runtime.exec", "refused", "a shell probe matching a root marker was refused");
        throw Java.use("java.io.IOException").$new("not found");
      }
      return this.exec(command);
    };
    report("java.lang.Runtime.exec", "installed", "shell probes matching root markers are refused");
  } catch (error) {
    report("java.lang.Runtime.exec", "unavailable", String(error));
  }

  try {
    const Build = Java.use("android.os.Build");
    const bump = counter("android.os.Build.TAGS");
    const tags = Build.TAGS.value;
    if (tags !== null && String(tags).indexOf("test-keys") !== -1) {
      Build.TAGS.value = "release-keys";
      bump();
      report("android.os.Build.TAGS", "installed", "test-keys reported as release-keys");
    } else {
      report("android.os.Build.TAGS", "available", "the build tags did not report test-keys");
    }
  } catch (error) {
    report("android.os.Build.TAGS", "unavailable", String(error));
  }

  try {
    const PackageManager = Java.use("android.app.ApplicationPackageManager");
    const bump = counter("android.app.ApplicationPackageManager.getPackageInfo");
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (name, flags) {
      if (name === "com.topjohnwu.magisk" || name === "eu.chainfire.supersu" || name === "com.koushikdutta.superuser") {
        bump();
        report("android.app.ApplicationPackageManager.getPackageInfo", "refused", "a root-manager package query was refused");
        throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(name);
      }
      return this.getPackageInfo(name, flags);
    };
    report("android.app.ApplicationPackageManager.getPackageInfo", "installed", "root-manager package queries are refused");
  } catch (error) {
    report("android.app.ApplicationPackageManager.getPackageInfo", "unavailable", String(error));
  }
}

function hookObjC() {
  // -[NSFileManager fileExistsAtPath:] is the single path probe the documented
  // jailbreak checks share. An Objective-C implementation slot holds a
  // NativePointer, not a JS function: the bridge's setter compares pointers
  // (`imp.equals(oldImp)`) and rejects a plain function. So the replacement is
  // built with ObjC.implement(method, callback), whose callback receives the
  // full method signature (self, sel, ...args), and the saved original is a
  // full-signature NativeFunction called with those same arguments.
  try {
    const NSFileManager = ObjC.classes.NSFileManager;
    const selector = "- fileExistsAtPath:";
    const method = NSFileManager[selector];
    if (method === undefined) {
      report("NSFileManager.fileExistsAtPath", "unavailable", "the selector is not implemented");
      return;
    }
    const bump = counter("NSFileManager.fileExistsAtPath");
    const omit = omission("NSFileManager.fileExistsAtPath", "the path argument was not a readable object");
    const oldImpl = method.implementation;
    method.implementation = ObjC.implement(method, function (self, sel, path) {
      // ObjC.implement passes every '@' argument as the raw id pointer: it does
      // not wrap objects the way ObjC.registerClass method wrappers do. So the
      // path is read back through ObjC.Object here, and the saved original gets
      // the untouched pointer.
      let text = null;
      try {
        if (path !== null && !path.isNull()) text = new ObjC.Object(path).toString();
      } catch (error) {
        text = null;
      }
      if (text === null) {
        omit();
      } else if (matches(text)) {
        bump();
        return 0;
      }
      return oldImpl(self, sel, path);
    });
    report("NSFileManager.fileExistsAtPath", "installed", "jailbreak path markers report absent; a probe this agent cannot read is counted as an omission");
  } catch (error) {
    report("NSFileManager.fileExistsAtPath", "unavailable", String(error));
  }
}

if (Java.available) {
  Java.perform(function () {
    hookJava();
  });
} else {
  report("java", "unavailable", "the target has no Java runtime");
}

if (ObjC.available) {
  hookObjC();
} else {
  report("objc", "unavailable", "the target has no Objective-C runtime");
}
