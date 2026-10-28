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
  try {
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession === undefined) {
      report("NSURLSession.delegate", "unavailable", "NSURLSession is not loaded");
      return;
    }
    const bump = counter("NSURLSession.delegate");
    const selector = "- URLSession:didReceiveChallenge:completionHandler:";
    const method = NSURLSession[selector];
    if (method === undefined) {
      report("NSURLSession.delegate", "unavailable", "the delegate selector is not implemented by this class");
      return;
    }
    const replacement = ObjC.implement(NSURLSession, selector, function (handle, selectorName, session, challenge, completionHandler) {
      bump();
      // NSURLSessionAuthChallengeUseCredential with a credential built from
      // the presented server trust: the default handling (pinning included)
      // is skipped, and no certificate bytes leave the target.
      const space = new ObjC.Object(challenge).protectionSpace();
      const credential = ObjC.classes.NSURLCredential.credentialForTrust_(space.serverTrust());
      new ObjC.Block(completionHandler).implementation(1, credential);
    });
    ObjC.intercept(method, replacement);
    report("NSURLSession.delegate", "installed", "session-level challenge handler accepts the presented credential");
  } catch (error) {
    report("NSURLSession.delegate", "unavailable", String(error));
  }

  try {
    const NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
    if (NSURLSessionConfiguration === undefined) {
      report("NSURLSession.defaultSessionConfiguration", "unavailable", "NSURLSessionConfiguration is not loaded");
      return;
    }
    report("NSURLSession.defaultSessionConfiguration", "available", "session configuration class loaded");
  } catch (error) {
    report("NSURLSession.defaultSessionConfiguration", "unavailable", String(error));
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
