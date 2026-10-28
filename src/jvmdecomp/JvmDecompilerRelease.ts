/** Stable provider identity and caller-facing remediation for the JVM lane. */
export const JVM_DECOMPILER_PROVIDER_ID = "vineflower";

/** Provider name used in Evidence provenance. */
export const JVM_DECOMPILER_PROVIDER_NAME =
  "Vineflower (JVM class decompilation)";

/** Environment key selecting the caller's Vineflower JAR. */
export const VINEFLOWER_JAR_ENV = "REA_VINEFLOWER_JAR";

/** Remediation for an unset or unusable Vineflower selection. */
export const VINEFLOWER_JAR_REMEDIATION = `Download Vineflower yourself and point ${VINEFLOWER_JAR_ENV} at an absolute path to the existing JAR. REA never downloads, installs, or updates it`;

/** Remediation for a missing or unusable Java runtime. */
export const VINEFLOWER_JAVA_REMEDIATION = `Select a full JDK 11 or newer with JAVA_HOME (an absolute JDK home) or make java available on PATH, then verify it with java -version. REA does not install Java`;

/** Remediation for malformed decompiled output. */
export const VINEFLOWER_OUTPUT_REMEDIATION = `Confirm the selected Vineflower JAR writes .java sources for the input classes. REA parses declarations only and reports no partial success when no declaration is recognized`;

/**
 * Vineflower CLI/Java-output shapes are documented assumptions. No verified
 * Vineflower release is pinned; every result carries this note.
 */
export const JVM_LANE_UNVERIFIED_NOTE =
  "The Vineflower CLI and Java source shapes in this lane are documented assumptions; no verified Vineflower release is pinned yet.";
