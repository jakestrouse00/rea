/**
 * ClientHello fingerprint projection for retained pcap facts. Inputs are the
 * producer-reported tshark field spellings for one ClientHello; outputs are
 * value-free derived fingerprints. No certificate bytes, keying material or
 * server-side facts are examined, and recorded values are never fetched.
 */
import { createHash } from "node:crypto";

/** Producer-reported field facts for one ClientHello. */
export interface ClientHelloFacts {
  readonly server_name: string | null;
  readonly record_version: string | null;
  readonly hello_version: string | null;
  /** Cipher-suite values as the producer reported them. */
  readonly ciphers: readonly string[];
  /** Extension type values as the producer reported them. */
  readonly extensions: readonly string[];
  /** Supported-group (elliptic curve) values as the producer reported them. */
  readonly curves: readonly string[];
  /** EC point-format values as the producer reported them. */
  readonly ec_point_formats: readonly string[];
  /** ALPN protocol values as the producer reported them. */
  readonly alpn: readonly string[];
}

export interface ClientHelloFingerprints {
  /** Original JA3 (MD5), null when the producer reported no handshake version. */
  readonly ja3: string | null;
  /** JA4 (FoxIO), null when the producer reported no handshake version. */
  readonly ja4: string | null;
}

/** Documented accuracy limits for the derived fingerprints. */
export const TLS_FINGERPRINT_LIMITATIONS: readonly string[] = [
  "JA3 is the original (not GREASE-stripped) MD5 of comma-joined ClientHello facts in JA3's integer form: handshake version, ascending-sorted cipher suites, extension types, supported groups and EC point formats. Producer values without a numeric spelling (named curves such as x25519, formatted point names) sort as lower-case text after the numeric values, so such values project a producer-spelling-dependent fingerprint rather than canonical JA3.",
  "JA4 follows the FoxIO layout (TCP protocol character 't', two-digit TLS version, SNI 'd'/'i', two-digit cipher and extension counts capped at 99, ALPN first-and-last characters) with RFC 8701 GREASE values removed from counts and hashes, but remains approximate: the TLS-version source is the reported handshake version rather than FoxIO's supported-version derivation, FoxIO's fold of signature-algorithm values into the extension-list hash is not reproduced (this projection does not retain signature algorithms), producer-reported non-numeric field spellings are not translated, and an empty cipher or extension list is hashed as the single character `0` rather than FoxIO's 48-zero sentinel. Do not treat the result as a verified FoxIO fingerprint match.",
  "ClientHello fingerprints are derived only from retained producer field values; no certificate bytes or keys are examined, and a fingerprint's presence never establishes a client- or vendor-behavior identity.",
];

/**
 * Numeric value of one producer field token: an explicit 0x-prefixed spelling
 * is hexadecimal, a bare digit run is decimal, and any other spelling (an
 * unsupported producer name) has no numeric value.
 */
const numericValue = (token: string): number | null =>
  /^0[xX][0-9a-fA-F]+$/u.test(token)
    ? parseInt(token.slice(2), 16)
    : /^\d+$/u.test(token)
      ? parseInt(token, 10)
      : null;

/** JA3's token form: the numeric integer, or the lower-case producer text. */
const ja3Token = (token: string): number | string =>
  numericValue(token) ?? token.toLowerCase();

const compareNumbers = (a: number, b: number): number => a - b;

/**
 * JA3 sorts every fact list ascending; numeric tokens sort numerically first
 * and producer text sorts after by code point.
 */
const sortedJa3 = (values: readonly string[]): string =>
  values
    .map(ja3Token)
    .sort((a, b) =>
      typeof a === "number" && typeof b === "number"
        ? compareNumbers(a, b)
        : typeof a === "number"
          ? -1
          : typeof b === "number"
            ? 1
            : a < b
              ? -1
              : a > b
                ? 1
                : 0,
    )
    .map((value) => String(value))
    .join("-");

/** RFC 8701 reserved 16-bit GREASE pattern (0x?a?a: second and fourth nibbles are 0xa, first equals third). */
const isGrease16 = (value: number): boolean =>
  (value & 0x0f) === 0x0a &&
  ((value >> 8) & 0xf) === 0x0a &&
  ((value >> 12) & 0xf) === ((value >> 4) & 0xf);

/** Four-digit lower-case hex of a numeric field value, or null without one. */
const hexValue = (token: string): string | null => {
  const value = numericValue(token);
  return value === null ? null : value.toString(16).padStart(4, "0");
};

const strippedSortedHex = (values: readonly string[]): string[] =>
  values
    .map((value) => hexValue(value))
    .filter(
      (value): value is string =>
        value !== null &&
        value.length === 4 &&
        !isGrease16(parseInt(value, 16)),
    )
    .sort();

/** FoxIO JA4's two-digit TLS version code, or null without a mapped version. */
const ja4Version = (
  helloVersion: string | null,
): "13" | "12" | "11" | "10" | null => {
  const value = numericValue(helloVersion ?? "");
  switch (value) {
    case 0x0304:
      return "13";
    case 0x0303:
      return "12";
    case 0x0302:
      return "11";
    case 0x0301:
      return "10";
    default:
      return null;
  }
};

const truncated = (values: readonly string[]): string =>
  createHash("sha256").update(values.join(",")).digest("hex").slice(0, 12);

/** Two-digit decimal count, capped at 99 as FoxIO's specification requires. */
const counted = (n: number): string => String(Math.min(n, 99)).padStart(2, "0");

/** FoxIO ALPN part: first and last character of the first offered protocol, lower-case; "00" when absent. */
const alpnPart = (alpn: readonly string[]): string => {
  const protocol = alpn[0]?.toLowerCase() ?? "";
  return protocol === ""
    ? "00"
    : `${protocol.slice(0, 1)}${protocol.slice(-1)}`;
};

/**
 * Derive JA3 and JA4 from one ClientHello's retained field facts, without
 * touching certificate or key values. Both stay null when the producer
 * reported no handshake version, so unknown facts never project an invented
 * identity.
 */
export const clientHelloFingerprints = (
  facts: ClientHelloFacts,
): ClientHelloFingerprints => {
  const ja4Code = ja4Version(facts.hello_version);
  const ja3 =
    ja4Code === null
      ? null
      : createHash("md5")
          .update(
            [
              String(numericValue(facts.hello_version ?? "")),
              sortedJa3(facts.ciphers),
              sortedJa3(facts.extensions),
              sortedJa3(facts.curves),
              sortedJa3(facts.ec_point_formats),
            ].join(","),
          )
          .digest("hex");
  const ciphers = strippedSortedHex(facts.ciphers);
  const extensions = strippedSortedHex(facts.extensions);
  const ja4 =
    ja4Code === null
      ? null
      : [
          `t${ja4Code}${facts.server_name === null ? "i" : "d"}${counted(ciphers.length)}${counted(extensions.length)}${alpnPart(facts.alpn)}`,
          truncated(ciphers.length === 0 ? ["0"] : ciphers),
          truncated(extensions.length === 0 ? ["0"] : extensions),
        ].join("_");
  return { ja3, ja4 };
};
