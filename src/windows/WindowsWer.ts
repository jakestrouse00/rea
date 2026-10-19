import type {
  WerField,
  WerReport,
  WerSignature,
} from "../domain/windowsArtifacts/werReport.js";
import type { InspectWerReportInput } from "../domain/windowsArtifacts/werReport.js";

/**
 * Text Windows Error Reporting (.wer) reader. WER writes UTF-16LE key=value
 * lines; this reader decodes the exact bytes, groups `Sig[N]` / `DynamicSig[N]`
 * module-signature entries, and preserves every other line verbatim. Values —
 * including paths, usernames and version strings — are recorded unmodified:
 * redaction decisions belong to the caller, not this producer.
 */
export const WER_INPUT_BYTES = 64 * 1024 * 1024;
/** One WER report is far smaller; this cap also bounds the preserved arrays. */
export const WER_MAX_LINES = 65536;

export class WerFormatFailure extends Error {
  readonly kind: "malformed";
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "WerFormatFailure";
    this.kind = "malformed";
  }
}

const SIG_KEY = /^(Sig\[(\d+)\]|DynamicSig\[(\d+)\])\.(\w+)$/u;

const decode = (
  bytes: Buffer,
): {
  text: string;
  encoding: WerReport["encoding"];
  hadByteOrderMark: boolean;
} => {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    let text: string;
    try {
      text = new TextDecoder("utf-16le", { fatal: true }).decode(
        bytes.subarray(2),
      );
    } catch (cause: unknown) {
      throw new WerFormatFailure(
        "Selected artifact declares a UTF-16LE byte-order mark but its bytes do not decode as UTF-16LE.",
        { cause },
      );
    }
    return { text, encoding: "utf-16le", hadByteOrderMark: true };
  }
  const evenLength = bytes.length % 2 === 0;
  const looksUtf16Le =
    evenLength &&
    bytes.length >= 20 &&
    bytes.filter((byte, index) => index % 2 === 1 && byte === 0x00).length >=
      bytes.length / 4;
  if (!looksUtf16Le) {
    const hasUtf8Mark =
      bytes.length >= 3 &&
      bytes[0] === 0xef &&
      bytes[1] === 0xbb &&
      bytes[2] === 0xbf;
    const asciiOnly = bytes.every((byte) => byte < 0x80);
    return {
      text: (hasUtf8Mark ? bytes.subarray(3) : bytes).toString("utf8"),
      encoding: asciiOnly ? "ascii" : "utf-8",
      hadByteOrderMark: hasUtf8Mark,
    };
  }
  let text: string;
  try {
    text = new TextDecoder("utf-16le", { fatal: true }).decode(bytes);
  } catch (cause: unknown) {
    throw new WerFormatFailure(
      "Selected artifact is not decodable as the UTF-16LE text WER reports use, and does not carry a UTF-16LE byte-order mark.",
      { cause },
    );
  }
  return { text, encoding: "utf-16le", hadByteOrderMark: false };
};

/**
 * Parse one complete bounded WER report into the structured observation.
 * Throws a typed `WerFormatFailure` for undecodable bytes; no reported value
 * is ever rewritten, defaulted or inferred from its key name.
 */
export const parseWindowsWerReport = (
  snapshot: { readonly bytes: Buffer; readonly sha256: string },
  input: InspectWerReportInput,
): WerReport => {
  const { text, encoding, hadByteOrderMark } = decode(snapshot.bytes);
  const rawLines = text.split(/\r\n|\n|\r/u);
  if (rawLines.length > WER_MAX_LINES)
    throw new WerFormatFailure(
      `Selected artifact declares ${String(rawLines.length)} lines above the ${String(WER_MAX_LINES)} line budget`,
    );
  const fields: WerField[] = [];
  const signatures = new Map<string, WerSignature>();
  const unparsedLines: string[] = [];
  let lineCount = 0;
  for (const line of rawLines) {
    if (line === "" && lineCount === rawLines.length - 1) continue;
    lineCount += 1;
    const separator = line.indexOf("=");
    if (separator <= 0) {
      unparsedLines.push(line);
      continue;
    }
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    fields.push({ key, value });
    const match = SIG_KEY.exec(key);
    if (match !== null && match[1] !== undefined) {
      const group = match[1].startsWith("Dynamic")
        ? "dynamic-sig"
        : ("sig" as WerSignature["group"]);
      const indexText = match[2] ?? match[3];
      if (indexText === undefined) continue;
      const index = Number(indexText);
      const groupKey = `${group}_${String(index)}`;
      const signature = signatures.get(groupKey) ?? {
        group: group as WerSignature["group"],
        index,
        fields: [],
      };
      signature.fields.push({
        key: key.slice(key.lastIndexOf(".") + 1),
        value,
      });
      signatures.set(groupKey, signature);
    }
  }
  const limitations: string[] = [
    "Every field value is preserved exactly as written; REA applies no secrecy inference and no redaction.",
    "Signatures group their recorded key/value pairs; no module, version or fault meaning is derived from names.",
  ];
  return {
    artifact: {
      path: input.path,
      sha256: snapshot.sha256,
      bytes: snapshot.bytes.length,
    },
    encoding,
    had_byte_order_mark: hadByteOrderMark,
    line_count: lineCount,
    fields,
    signatures: [...signatures.values()],
    unparsed_lines: unparsedLines,
    complete: true,
    limitations,
  };
};
