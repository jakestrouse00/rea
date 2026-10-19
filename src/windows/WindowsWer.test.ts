import { expect, it } from "vitest";

import {
  werReportSchema,
  type WerReport,
} from "../domain/windowsArtifacts/werReport.js";
import { parseWindowsWerReport, WerFormatFailure } from "./WindowsWer.js";

const utf16 = (text: string, withMark = true): Buffer => {
  const body = Buffer.from(text, "utf16le");
  return withMark ? Buffer.concat([Buffer.from([0xff, 0xfe]), body]) : body;
};

const parse = (bytes: Buffer): WerReport =>
  parseWindowsWerReport(
    { bytes, sha256: "0".repeat(64) },
    { path: "/artifacts/report.wer" },
  );

const REPRESENTATIVE_TEXT = [
  "EventType=APPCRASH",
  "Sig[0].Name=Application Name",
  "Sig[0].Value=example.exe",
  "Sig[0].Name=Application Version",
  "Sig[0].Value=1.2.3.4",
  "DynamicSig[1].Name=OS Version",
  "DynamicSig[1].Value=6.1.7601.2.1.0.256.48",
  "UI[2]=C:\\Users\\alice\\AppData\\Local\\Temp\\WER6.tmp",
  "AppPath=C:\\Program Files\\Example\\example.exe",
].join("\r\n");

it("decodes UTF-16LE fields exactly as written, with no redaction or inference", () => {
  const report = parse(utf16(REPRESENTATIVE_TEXT));
  expect(report.encoding).toBe("utf-16le");
  expect(report.had_byte_order_mark).toBe(true);
  expect(report.artifact.path).toBe("/artifacts/report.wer");
  const field = report.fields.find(({ key }) => key === "AppPath");
  expect(field).toEqual({
    key: "AppPath",
    value: "C:\\Program Files\\Example\\example.exe",
  });
  expect(report.fields.map(({ key }) => key)).toContain("UI[2]");
  expect(werReportSchema.safeParse(report).success).toBe(true);
});

it("groups Sig and DynamicSig entries by their bracketed index", () => {
  const report = parse(utf16(REPRESENTATIVE_TEXT));
  expect(report.signatures).toHaveLength(2);
  const [sig, dynamicSig] = report.signatures;
  expect(sig).toEqual({
    group: "sig",
    index: 0,
    fields: [
      { key: "Name", value: "Application Name" },
      { key: "Value", value: "example.exe" },
      { key: "Name", value: "Application Version" },
      { key: "Value", value: "1.2.3.4" },
    ],
  });
  expect(dynamicSig).toEqual({
    group: "dynamic-sig",
    index: 1,
    fields: [
      { key: "Name", value: "OS Version" },
      { key: "Value", value: "6.1.7601.2.1.0.256.48" },
    ],
  });
});

it("preserves every field and signature value byte-for-byte, including usernames", () => {
  const hostile =
    "AppPath=C:\\Users\\Alice Söderström\\x.exe\r\nSig[3].Name=Ünïcödé & <tag>\r\n";
  const report = parse(utf16(hostile));
  expect(report.fields[0]?.value).toBe("C:\\Users\\Alice Söderström\\x.exe");
  expect(report.signatures[0]?.group).toBe("sig");
  expect(report.signatures[0]?.index).toBe(3);
  expect(
    report.limitations.some((limitation) =>
      limitation.includes("no secrecy inference"),
    ),
  ).toBe(true);
});

it("falls back to UTF-8 and ASCII decodes, and reports the byte-order-mark facts", () => {
  const report = parse(
    Buffer.from("EventType=APPCRASH\nAppPath=x.exe\n", "ascii"),
  );
  expect(report.encoding).toBe("ascii");
  expect(report.had_byte_order_mark).toBe(false);
  expect(report.fields).toHaveLength(2);
  const utf8Marked = parse(
    Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from("A=B\n", "utf8"),
    ]),
  );
  expect(utf8Marked.encoding).toBe("utf-8");
  expect(utf8Marked.had_byte_order_mark).toBe(true);
});

it("treats UTF-16LE reports without a byte-order mark by their zero-byte pattern", () => {
  const report = parse(utf16(REPRESENTATIVE_TEXT, false));
  expect(report.encoding).toBe("utf-16le");
  expect(report.had_byte_order_mark).toBe(false);
  expect(report.fields).toHaveLength(9);
});

it("preserves lines without a key=value separator as unparsed text", () => {
  const report = parse(
    utf16("EventType=APPCRASH\r\nnot a field\r\n\r\nSig[0].Name=name\r\n"),
  );
  expect(report.unparsed_lines).toEqual(["not a field", ""]);
  expect(report.line_count).toBe(4);
  expect(report.complete).toBe(true);
});

it("fails typed for UTF-16 bytes that do not decode (unpaired surrogates)", () => {
  const invalid = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from([0x00, 0xd8, 0x00, 0xd8, 0x00, 0xd8, 0x00, 0xd8]),
  ]);
  expect(() => parse(invalid)).toThrow(WerFormatFailure);
});

it("keys without any separator character remain unparsed, not dropped", () => {
  const report = parse(utf16("A\r\nB\r\n"));
  expect(report.unparsed_lines).toEqual(["A", "B"]);
  expect(report.fields).toHaveLength(0);
});
