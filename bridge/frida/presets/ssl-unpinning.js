// REA reference Frida agent (MIT, authored for this repository).
//
// Minimal certificate-pinning visibility-and-bypass preset. It is not a copy
// of any upstream project; it implements the publicly documented shape of the
// common Android/iOS pinning checks so a caller can observe which checks exist
// and let the session continue past them. Every hook reports structure only:
// a hook name, whether it resolved, and a counter. No certificate, key,
// hostname, or payload byte is sent.
//
// Emitted rows: {"event":"rea-preset","preset":"ssl-unpinning","hook":NAME,
//               "status":"installed"|"unavailable"|"failed","detail":...}
// and {"event":"rea-preset-bypass","hook":NAME,"count":N} per intercepted call.
//
// Android hooks replace the Java method implementation; the iOS hook attaches
// to Security.framework's trust evaluation. Both are the documented Frida
// idioms, so a hook either installs or reports why it could not.

const PRESET = "ssl-unpinning";

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

function hookJava() {
  try {
    const CertificatePinner = Java.use("okhttp3.CertificatePinner");
    const bump = counter("okhttp3.CertificatePinner.check");
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (host, pins) {
      bump();
      return;
    };
    report("okhttp3.CertificatePinner.check", "installed", "overload(String,List)");
  } catch (error) {
    report("okhttp3.CertificatePinner.check", "unavailable", String(error));
  }

  try {
    const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    const bump = counter("conscrypt.TrustManagerImpl.checkTrustedRecursive");
    TrustManagerImpl.checkTrustedRecursive.implementation = function () {
      bump();
      return Java.use("java.util.ArrayList").$new();
    };
    report("conscrypt.TrustManagerImpl.checkTrustedRecursive", "installed", "returns an empty chain list");
  } catch (error) {
    report("conscrypt.TrustManagerImpl.checkTrustedRecursive", "unavailable", String(error));
  }

  try {
    const X509TrustManagerExtensions = Java.use("android.net.http.X509TrustManagerExtensions");
    const bump = counter("X509TrustManagerExtensions.checkServerTrusted");
    X509TrustManagerExtensions.checkServerTrusted.implementation = function (chain, authType, host) {
      bump();
      return Java.use("java.util.ArrayList").$new(chain);
    };
    report("X509TrustManagerExtensions.checkServerTrusted", "installed", "returns the presented chain");
  } catch (error) {
    report("X509TrustManagerExtensions.checkServerTrusted", "unavailable", String(error));
  }

  try {
    const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    report("javax.net.ssl.HostnameVerifier", "available", "interface loaded; per-instance verifiers are not enumerated");
    void HostnameVerifier;
  } catch (error) {
    report("javax.net.ssl.HostnameVerifier", "unavailable", String(error));
  }
}

function hookObjC() {
  // Every iOS TLS trust decision funnels through Security.framework's
  // evaluation entry point, so hooking it covers NSURLSession, WebKit, and
  // third-party clients without naming an app-specific delegate class. The
  // NSURLSession delegate method is implemented by the app, not by
  // NSURLSession, so this agent does not claim to hook it.
  try {
    const evaluate = Module.findExportByName(null, "SecTrustEvaluateWithError");
    if (evaluate === null) {
      report("SecTrustEvaluateWithError", "unavailable", "the symbol is not exported on this OS version");
      return;
    }
    const bump = counter("SecTrustEvaluateWithError");
    Interceptor.attach(evaluate, {
      onLeave(retval) {
        bump();
        // BOOL result: the presented chain is accepted. Pinning is skipped
        // without reading any certificate byte in this agent.
        retval.replace(ptr(1));
      },
    });
    report("SecTrustEvaluateWithError", "installed", "trust evaluation reports success for every chain");
  } catch (error) {
    report("SecTrustEvaluateWithError", "unavailable", String(error));
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
