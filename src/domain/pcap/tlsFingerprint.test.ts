import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import {
  clientHelloFingerprints,
  TLS_FINGERPRINT_LIMITATIONS,
  type ClientHelloFacts,
} from "./tlsFingerprint.js";

const md5 = (value: string) => createHash("md5").update(value).digest("hex");
const sha12 = (value: string) =>
  createHash("sha256").update(value).digest("hex").slice(0, 12);

const base: ClientHelloFacts = {
  server_name: "example.example",
  record_version: "0x0303",
  hello_version: "0x0303",
  ciphers: ["0xc02f", "0xc02b", "0xc030", "0xc02c"],
  extensions: ["0", "10", "11", "13", "23", "35", "43", "51", "0xff01"],
  curves: ["23", "24", "29"],
  ec_point_formats: ["0"],
  alpn: ["h2"],
};

it("projects JA3 as the original ascending MD5 of version, ciphers, extensions, curves, point formats", () => {
  const { ja3, ja4 } = clientHelloFingerprints(base);
  expect(ja3).toBe(
    md5("771,49195-49196-49199-49200,0-10-11-13-23-35-43-51-65281,23-24-29,0"),
  );
  expect(ja3).toMatch(/^[0-9a-f]{32}$/);
});

it("projects JA4 in FoxIO layout with GREASE stripped from counts and hashes", () => {
  const { ja4 } = clientHelloFingerprints(base);
  expect(ja4).toBe(
    `t12d0409h2_${sha12("c02b,c02c,c02f,c030")}_${sha12(
      "0000,000a,000b,000d,0017,0023,002b,0033,ff01",
    )}`,
  );
  // Part B ciphers keep four-digit lowercase hex sorted ascending; part C
  // extension types are sorted, zero-padded and GREASE-free.
  expect(ja4).toMatch(/^t12d0409h2_[0-9a-f]{12}_[0-9a-f]{12}$/u);
});

it("strips exactly the RFC 8701 16-bit GREASE values from JA4 counts", () => {
  const { ja4 } = clientHelloFingerprints({
    ...base,
    ciphers: ["0x0a0a", "0x1301", "0xfafa", "0xc02b"],
    extensions: ["0x0a0a", "0", "0x1a1a", "11"],
  });
  // 2 cipher suites and 2 extensions remain after GREASE removal.
  expect(ja4?.startsWith("t12d0202h2_")).toBe(true);
});

it("reports no SNI as 'i' and lowercases the first-and-last-character ALPN", () => {
  const { ja4 } = clientHelloFingerprints({
    ...base,
    server_name: null,
    alpn: ["http/1.1"],
  });
  expect(ja4?.startsWith("t12i0409h1_")).toBe(true);
  const absent = clientHelloFingerprints({
    ...base,
    server_name: null,
    alpn: [],
  });
  expect(absent.ja4?.startsWith("t12i040900_")).toBe(true);
});

it("keeps producer-reported names after numeric values and documents the spelling dependence", () => {
  const { ja3 } = clientHelloFingerprints({
    ...base,
    curves: ["x25519", "23"],
  });
  expect(ja3).toBe(
    md5("771,49195-49196-49199-49200,0-10-11-13-23-35-43-51-65281,23-x25519,0"),
  );
  expect(
    TLS_FINGERPRINT_LIMITATIONS.some((limitation) =>
      limitation.includes("producer-spelling-dependent"),
    ),
  ).toBe(true);
  expect(
    TLS_FINGERPRINT_LIMITATIONS.some(
      (limitation) =>
        limitation.includes("remains approximate") &&
        limitation.includes("not reproduced"),
    ),
  ).toBe(true);
});

it("returns null fingerprints when the producer reported no handshake version", () => {
  const missing = clientHelloFingerprints({
    ...base,
    hello_version: null,
    record_version: "0x0303",
  });
  expect(missing).toEqual({ ja3: null, ja4: null });
  const unparseable = clientHelloFingerprints({
    ...base,
    hello_version: "unknown",
  });
  expect(unparseable.ja3).toBeNull();
  expect(unparseable.ja4).toBeNull();
});

it("maps handshake versions to FoxIO two-digit TLS codes", () => {
  for (const [version, prefix] of [
    ["0x0304", "t13"],
    ["0x0303", "t12"],
    ["0x0302", "t11"],
    ["0x0301", "t10"],
  ] as const)
    expect(
      clientHelloFingerprints({
        ...base,
        hello_version: version,
      }).ja4?.startsWith(`${prefix}d0409h2_`),
    ).toBe(true);
});
