/** Fixed policy for the mitmproxy interception lane. */
export const MITM_LIMITS = {
  /** Longest structure-stream line retained before it is refused as a line. */
  maxStreamLineBytes: 256 * 1_024,
  /** Structure-stream lines that do not parse before the session is degraded. */
  maxMalformedLines: 32,
  /** Distinct endpoints retained per session. */
  maxEndpoints: 512,
  /** Parameter rows retained per endpoint. */
  maxParametersPerEndpoint: 32,
  /** Observed types retained for one parameter name. */
  maxParameterTypes: 4,
  /** Header names retained per endpoint and direction. */
  maxHeaderNames: 64,
  /** Distinct response statuses retained per endpoint. */
  maxStatusCodes: 16,
  /** Response-shape keys retained at one object level. */
  maxShapeKeys: 24,
  /** Response-shape nesting retained from the addon. */
  maxShapeDepth: 4,
  /** Endpoint rows returned by one inventory page. */
  maxListedEndpoints: 20,
  /** Armed rewrite rules per session. */
  maxArmedRules: 32,
  /** A rewrite rule stays armed at most this long. */
  maxRuleTtlMs: 3_600_000,
  /** Default lifetime of one rewrite rule. */
  defaultRuleTtlMs: 300_000,
  /** Header edits one rule may carry. */
  maxRuleHeaderEdits: 32,
  /** Query edits one rule may carry. */
  maxRuleQueryEdits: 32,
  /** Replacement body one rule may carry. */
  maxRuleBodyBytes: 1 * 1_024 * 1_024,
  /** Rule decisions retained in one ledger. */
  maxRetainedDecisions: 256,
  /** Startup advertisement deadline. */
  defaultStartTimeoutMs: 30_000,
  /** Longest admitted startup deadline. */
  maxStartTimeoutMs: 120_000,
  /** One on-disk replayable entry record. */
  maxEntryRecordBytes: 1 * 1_024 * 1_024,
  /** Captured entries whose replay record REA still tracks. */
  maxTrackedEntries: 1_024,
  /** Captured request or response body retained on disk. */
  maxHeldBodyBytes: 64 * 1_024 * 1_024,
  /** Loopback listener used when the caller selects no port. */
  defaultListenPort: 8_080,
  /** Largest listen port number. */
  maxListenPort: 65_535,
} as const;

/** On-disk schema version of one replayable entry record. */
export const MITM_ENTRY_RECORD_VERSION = 1;

/** Protocol version spoken by the generated addon and this parser. */
export const MITM_PROTOCOL_VERSION = 1;

/** Addon script the operator generates into {{REA_MITM_ADDON_DIR}}. */
export const MITM_ADDON_FILE_NAME = "rea_mitm_addon.py";

/** Addon identity the startup advertisement must carry. */
export const MITM_ADDON_ID = "rea-mitm-addon";

/** Provider identity for the interception lane. */
export const MITM_PROVIDER_ID = "rea-mitm";

export const MITM_PROVIDER = {
  id: MITM_PROVIDER_ID,
  name: "REA mitmproxy interception lane",
  version: "1",
} as const;

/** Environment variable naming the caller-supplied mitmdump binary. */
export const MITM_COMMAND_ENV = "REA_MITMDUMP_COMMAND";

/** Environment variable naming the directory holding the generated addon. */
export const MITM_ADDON_DIR_ENV = "REA_MITM_ADDON_DIR";

/** Environment variable naming the caller-supplied Arjun binary (documented hook). */
export const MITM_ARJUN_COMMAND_ENV = "REA_ARJUN_COMMAND";

export const MITM_COMMAND_REMEDIATION = `Set ${MITM_COMMAND_ENV} to the absolute path of a caller-supplied mitmdump binary from a mitmproxy 12.x installation. REA does not download, install, or upgrade mitmproxy, and it never edits a system or device trust store.`;

export const MITM_ADDON_DIR_REMEDIATION = `Generate the addon with "node bridge/mitm/generate_addon.ts --out <absolute-directory>", then set ${MITM_ADDON_DIR_ENV} to that absolute directory. The directory must contain ${MITM_ADDON_FILE_NAME}.`;

export const MITM_TOOL_REMEDIATION = `Set ${MITM_COMMAND_ENV} to an absolute mitmdump binary and ${MITM_ADDON_DIR_ENV} to the absolute directory holding ${MITM_ADDON_FILE_NAME}, then restart REA. See docs/mitm-interception.md.`;

export const MITM_ARJUN_COMMAND_REMEDIATION = `Parameter mining is documented, not shipped: run a caller-supplied Arjun binary (${MITM_ARJUN_COMMAND_ENV}) yourself against the candidate pool export_endpoint_inventory produces, rate-limited and against lab-owned targets only. REA adds no arjun tool in this release.`;

/** Loopback listener address; the proxy never binds a routable interface. */
export const MITM_LISTEN_HOST = "127.0.0.1";

/** Locations a parameter name can be observed in. */
export const MITM_PARAMETER_LOCATIONS = ["query", "path", "body"] as const;
export type MitmParameterLocation = (typeof MITM_PARAMETER_LOCATIONS)[number];

/** Type classes one parameter name is reported with; never its values. */
export const MITM_PARAMETER_TYPES = [
  "string",
  "integer",
  "number",
  "boolean",
  "null",
  "object",
  "array",
  "uuid",
  "hex",
] as const;
export type MitmParameterType = (typeof MITM_PARAMETER_TYPES)[number];

/** How one interception session ended its capture. */
export const MITM_SESSION_STATES = [
  "capturing",
  "degraded",
  "stopped",
] as const;
export type MitmSessionState = (typeof MITM_SESSION_STATES)[number];

/** Why REA released one rewrite rule. */
export const MITM_RULE_RELEASE_REASONS = [
  "cleared",
  "expired",
  "server-close",
] as const;
export type MitmRuleReleaseReason = (typeof MITM_RULE_RELEASE_REASONS)[number];

/** Phase one rewrite rule applies to. */
export const MITM_RULE_PHASES = ["request", "response"] as const;
export type MitmRulePhase = (typeof MITM_RULE_PHASES)[number];

/** Applications the per-app proxy guidance is written for. */
export const MITM_TARGET_APPS = [
  "browser",
  "android-app",
  "ios-app",
  "desktop-app",
  "other",
] as const;
export type MitmTargetApp = (typeof MITM_TARGET_APPS)[number];

/** One app-specific instruction telling the caller where to point the proxy. */
export interface MitmProxyGuidance {
  readonly target_app: MitmTargetApp;
  /** True when the guidance only changes this app's own proxy configuration. */
  readonly per_app_only: true;
  readonly steps: readonly string[];
  /** What this lane explicitly does not change on the device or host. */
  readonly out_of_scope: readonly string[];
}

const PROXY_OUT_OF_SCOPE = [
  "REA never adds a CA certificate to a system, browser, or device trust store; importing the mitmproxy CA is the caller's own, reversible change.",
  "REA never intercepts a device or host system-wide: no global proxy, no Wi-Fi proxy payload, no transparent redirect, and no firewall rule.",
  "REA never disables certificate pinning inside the target; a pinned client refuses this proxy instead.",
] as const;

/**
 * Per-app proxy configuration only. Every step changes one application's own
 * proxy setting (environment variables, a per-app debug bridge, or an
 * instrumented launch), and the out-of-scope entries name what stays untouched.
 */
export const mitmProxyGuidance = (
  targetApp: MitmTargetApp,
  listenPort: number,
  appIdentifier: string | undefined,
): MitmProxyGuidance => {
  const endpoint = `${MITM_LISTEN_HOST}:${String(listenPort)}`;
  switch (targetApp) {
    case "browser":
      return {
        target_app: targetApp,
        per_app_only: true,
        steps: [
          `Launch only the browser profile under test with --proxy-server=http://${endpoint} and a separate --user-data-dir so the system and other profiles stay unproxied.`,
          "Import the mitmproxy CA into that profile only, or launch with a profile that already trusts it: http://mitm.it serves the certificate while the proxy is running.",
        ],
        out_of_scope: PROXY_OUT_OF_SCOPE,
      };
    case "android-app":
      return {
        target_app: targetApp,
        per_app_only: true,
        steps: [
          `In the target package's own debuggable build, set the process proxy with "adb reverse tcp:${String(listenPort)} tcp:${String(listenPort)}" plus a per-app network-security-config that trusts the mitmproxy CA for that package only.`,
          "A release build without a debuggable webview keeps its pinning and refuses this proxy; that refusal is the observation.",
        ],
        out_of_scope: PROXY_OUT_OF_SCOPE,
      };
    case "ios-app":
      return {
        target_app: targetApp,
        per_app_only: true,
        steps: [
          `Point only the instrumented simulator or lab-owned device app at ${endpoint} through an explicit URLSession configuration proxy, or launch it under a caller-owned debug harness.`,
          "Importing the mitmproxy CA into an iOS trust store is out of scope and stays the caller's own reversible change.",
        ],
        out_of_scope: PROXY_OUT_OF_SCOPE,
      };
    case "desktop-app":
      return {
        target_app: targetApp,
        per_app_only: true,
        steps: [
          `Launch the application under test with HTTPS_PROXY=http://${endpoint} and HTTP_PROXY=http://${endpoint} in its own environment, so the rest of the host stays unproxied.`,
          "If the application honours no proxy variable, instrument its own HTTP client instead of redirecting the host's traffic.",
        ],
        out_of_scope: PROXY_OUT_OF_SCOPE,
      };
    case "other":
      return {
        target_app: targetApp,
        per_app_only: true,
        steps: [
          `Configure only the application or harness under test to use the HTTP proxy at ${endpoint}.`,
          `Pass ${appIdentifier === undefined ? "the target's own identifier" : appIdentifier} to the caller-owned harness so the observation names the application, not the host.`,
        ],
        out_of_scope: PROXY_OUT_OF_SCOPE,
      };
  }
};
