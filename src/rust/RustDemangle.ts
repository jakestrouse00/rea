/**
 * Self-contained Rust symbol demangler for the legacy (`_ZN…E`) and v0 (`_R…`)
 * mangling schemes, following rustc-demangle's legacy escaping and the rustc
 * v0 grammar published at doc.rust-lang.org/rustc/symbol-mangling/v0.html.
 *
 * The demangler never performs unbounded work: input length, output length,
 * parse depth and every intermediate render are capped, and each failure is
 * returned as a structured reason instead of an exception.
 */

export type RustMangleFormat = "legacy" | "v0" | "other";

/** Structured demangling outcome; failures keep the attempted format. */
export interface RustDemangleResult {
  readonly demangled: string | null;
  readonly mangled: string;
  readonly format: RustMangleFormat;
  readonly failure_reason: string | null;
}

/** Maximum accepted mangled input length, in UTF-8 bytes. */
export const RUST_DEMANGLE_INPUT_BYTES = 16_384;
/** Maximum generated demangled output length, in UTF-16 code units. */
export const RUST_DEMANGLE_OUTPUT_CHARS = 16_384;
const MAX_PARSE_DEPTH = 64;

class DemangleFailure extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "DemangleFailure";
  }
}

/**
 * Classify a symbol name before demangling. `other` covers plain C names,
 * C++ Itanium names, and everything else that is not Rust-mangled; callers
 * must not run the Rust demanglers on those.
 */
export const classifyRustMangling = (
  name: string,
): "legacy" | "v0" | "other" => {
  const body = name.replace(/^_+/, "");
  if (body.startsWith("ZN")) return "legacy";
  if (/^R\d*[CMXYNIB]/u.test(body)) return "v0";
  return "other";
};

/** Demangle one Rust-mangled symbol, or return a structured failure. */
export const demangleRustSymbol = (mangled: string): RustDemangleResult => {
  const format = classifyRustMangling(mangled);
  if (format === "other")
    return {
      demangled: null,
      mangled,
      format: "other",
      failure_reason: "Name does not use a Rust mangling scheme",
    };
  if (Buffer.byteLength(mangled, "utf8") > RUST_DEMANGLE_INPUT_BYTES)
    return {
      demangled: null,
      mangled,
      format,
      failure_reason: `Mangled input exceeds the ${RUST_DEMANGLE_INPUT_BYTES} byte limit`,
    };
  try {
    const demangled =
      format === "legacy" ? demangleLegacy(mangled) : demangleV0(mangled);
    return { demangled, mangled, format, failure_reason: null };
  } catch (cause) {
    const failure =
      cause instanceof DemangleFailure
        ? cause
        : new DemangleFailure(
            String(cause instanceof Error ? cause.message : cause),
          );
    return { demangled: null, mangled, format, failure_reason: failure.reason };
  }
};

// ---------------------------------------------------------------------------
// Legacy scheme (`_ZN<len><name>…E`), mirroring rustc-demangle.
// ---------------------------------------------------------------------------

/**
 * Legacy `$…$` escapes, mirroring rustc-demangle's legacy Display mapping
 * (from the compiler's legacy symbol_names encoder).
 */
const LEGACY_ESCAPES: Record<string, string> = {
  SP: "@",
  BP: "*",
  RF: "&",
  LT: "<",
  GT: ">",
  LP: "(",
  RP: ")",
  C: ",",
};

const demangleLegacy = (mangled: string): string => {
  let body = mangled.replace(/^_+/, "");
  if (!body.startsWith("ZN"))
    throw new DemangleFailure("Legacy symbol name prefix is missing");
  body = body.slice(2);
  if (/[^\x00-\x7f]/u.test(body))
    throw new DemangleFailure("Legacy symbol bytes are not ASCII");
  const points = [...body];
  let cursor = 0;
  const elements: string[] = [];
  for (;;) {
    if (cursor >= points.length)
      throw new DemangleFailure("Legacy name ended before an identifier");
    let length = 0;
    let digits = 0;
    while (cursor < points.length) {
      const digit = points[cursor];
      if (digit === undefined) break;
      if (digit < "0" || digit > "9") break;
      length = length * 10 + digit.charCodeAt(0) - 48;
      if (length > points.length)
        throw new DemangleFailure("Legacy identifier length exceeds the input");
      cursor += 1;
      digits += 1;
    }
    if (digits === 0 || length === 0)
      throw new DemangleFailure("Legacy identifier length is missing or zero");
    if (length > points.length - cursor)
      throw new DemangleFailure("Legacy identifier length exceeds the input");
    elements.push(points.slice(cursor, cursor + length).join(""));
    cursor += length;
    if (cursor >= points.length)
      throw new DemangleFailure("Legacy name is missing its terminating E");
    if (points[cursor] === "E") {
      cursor += 1;
      break;
    }
    if (elements.length > 1024)
      throw new DemangleFailure("Legacy name has too many segments");
  }
  if (cursor < points.length) {
    const suffix = points.slice(cursor).join("");
    // rustc-demangle keeps a suffix only when it is `.…` with printable ASCII;
    // anything else makes the whole name print unchanged (here: a failure).
    if (!suffix.startsWith("."))
      throw new DemangleFailure("Legacy name has unexpected trailing bytes");
    if (!/^[\x21-\x7e]*$/u.test(suffix))
      throw new DemangleFailure("Legacy name has a non-symbol-like suffix");
  }
  const last = elements.at(-1);
  if (last !== undefined && isRustLegacyHash(last)) elements.pop();
  return checkOutput(elements.map(renderLegacyElement).join("::"));
};

const isRustLegacyHash = (value: string): boolean =>
  /^h[0-9a-fA-F]+$/u.test(value);

/** Unicode `Cc` control category: C0/C1 codes only. */
const isControlCodepoint = (codepoint: number): boolean =>
  codepoint <= 0x1f || (codepoint >= 0x7f && codepoint <= 0x9f);

/**
 * One legacy element rendered the way rustc-demangle's legacy Display loop
 * does: one element-leading `_` is stripped before `$`-escape handling, `..`
 * renders as `::`, and an unknown or malformed `$…$` escape abandons further
 * escape processing within the element and leaves the remainder verbatim.
 */
const renderLegacyElement = (raw: string): string => {
  let rest = raw.startsWith("_$") ? raw.slice(1) : raw;
  let out = "";
  for (;;) {
    if (rest.startsWith(".")) {
      if (rest.startsWith("..")) {
        out += "::";
        rest = rest.slice(2);
      } else {
        out += ".";
        rest = rest.slice(1);
      }
      continue;
    }
    if (rest.startsWith("$")) {
      const close = rest.indexOf("$", 1);
      if (close < 0) {
        out += rest;
        break;
      }
      const name = rest.slice(1, close);
      const after = rest.slice(close + 1);
      const known = LEGACY_ESCAPES[name];
      if (known !== undefined) {
        out += known;
        rest = after;
        continue;
      }
      if (/^u[0-9a-f]{1,6}$/u.test(name)) {
        const codepoint = Number.parseInt(name.slice(1), 16);
        if (codepoint <= 0x10_ff_ff && !isControlCodepoint(codepoint)) {
          out += String.fromCodePoint(codepoint);
          rest = after;
          continue;
        }
      }
      out += rest;
      break;
    }
    const index = rest.search(/[$.]/u);
    if (index < 0) {
      out += rest;
      break;
    }
    out += rest.slice(0, index);
    rest = rest.slice(index);
  }
  return out;
};

// ---------------------------------------------------------------------------
// v0 scheme (`_R…`), following the rustc v0 grammar.
// ---------------------------------------------------------------------------

const BASIC_TYPES: Record<string, string> = {
  a: "i8",
  b: "bool",
  c: "char",
  d: "f64",
  e: "str",
  f: "f32",
  h: "u8",
  i: "isize",
  j: "usize",
  l: "i32",
  m: "u32",
  n: "i128",
  o: "u128",
  s: "i16",
  t: "u16",
  u: "()",
  v: "...",
  x: "i64",
  y: "u64",
  z: "!",
  p: "_",
};

const SIGNED_CONST_TYPES = new Set(["a", "s", "l", "x", "n", "i"]);
const UNSIGNED_CONST_TYPES = new Set(["h", "t", "m", "y", "o", "j"]);
const PATH_TAGS = [67, 77, 88, 89, 78, 73, 66];

class V0Parser {
  #pos: number;
  #budget: number;
  #binderCount = 0;
  readonly #rendered = new Map<number, string>();

  constructor(readonly bytes: Buffer) {
    this.#pos = 0;
    this.#budget = RUST_DEMANGLE_OUTPUT_CHARS;
  }

  get done(): boolean {
    return this.#pos >= this.bytes.length;
  }

  peek(): number | undefined {
    return this.bytes[this.#pos];
  }

  next(): number {
    const byte = this.bytes[this.#pos];
    if (byte === undefined)
      throw new DemangleFailure("v0 symbol ended unexpectedly");
    this.#pos += 1;
    return byte;
  }

  charge(rendered: string): void {
    this.#budget -= rendered.length;
    if (this.#budget < 0)
      throw new DemangleFailure(
        `Demangled output exceeds the ${RUST_DEMANGLE_OUTPUT_CHARS} character limit`,
      );
  }

  decimal(): number {
    let value = 0;
    let digits = 0;
    for (;;) {
      const byte = this.peek();
      if (byte === undefined || byte < 48 || byte > 57) break;
      value = value * 10 + byte - 48;
      if (value > this.bytes.length)
        throw new DemangleFailure("v0 number exceeds the input size");
      this.#pos += 1;
      digits += 1;
    }
    if (digits === 0) throw new DemangleFailure("v0 decimal number is missing");
    return value;
  }

  /** Standard base-62 number: `_` alone is 0, any digit run encodes value-1. */
  base62(): bigint {
    const byte = this.peek();
    if (byte === undefined)
      throw new DemangleFailure("v0 base-62 number is truncated");
    if (byte === 95) {
      this.#pos += 1;
      return 0n;
    }
    let value = 0n;
    for (;;) {
      const digit = base62Digit(this.peek() ?? 0);
      if (digit === undefined)
        throw new DemangleFailure(
          "v0 base-62 number contains an invalid character",
        );
      value = value * 62n + BigInt(digit);
      this.#pos += 1;
      const terminator = this.peek();
      if (terminator === 95) {
        this.#pos += 1;
        return value + 1n;
      }
      if (terminator === undefined)
        throw new DemangleFailure("v0 base-62 number is truncated");
    }
  }

  small(value: bigint, label: string): number {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new DemangleFailure(`v0 ${label} exceeds its decodable range`);
    return Number(value);
  }

  identifier(): { text: string; disambiguator: bigint } {
    const { text, disambiguator } = this.#identifierBytes();
    this.charge(text);
    return { text, disambiguator };
  }

  #identifierBytes(): { text: string; disambiguator: bigint } {
    let disambiguator = 0n;
    if (this.peek() === 115) {
      this.#pos += 1;
      disambiguator = this.base62() + 1n;
    }
    let punycode = false;
    if (this.peek() === 117) {
      const following = this.bytes[this.#pos + 1];
      if (following !== undefined && following >= 48 && following <= 57) {
        punycode = true;
        this.#pos += 1;
      }
    }
    const length = this.decimal();
    if (this.peek() === 95) this.#pos += 1;
    if (length > this.bytes.length - this.#pos)
      throw new DemangleFailure("v0 identifier bytes exceed the input");
    const raw = this.bytes.subarray(this.#pos, this.#pos + length);
    this.#pos += length;
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      throw new DemangleFailure("v0 identifier is not valid UTF-8");
    }
    if (punycode) text = decodePunycode(text);
    return { text, disambiguator };
  }

  lifetime(): number {
    if (this.peek() !== 76)
      throw new DemangleFailure("v0 symbol is missing its lifetime marker");
    this.#pos += 1;
    return this.small(this.base62(), "lifetime index");
  }

  record(start: number, rendered: string): void {
    this.#rendered.set(start, rendered);
    this.charge(rendered);
  }

  path(depth: number, inType = false): string {
    const start = this.#pos;
    const rendered = this.#renderPath(depth, inType);
    this.record(start, rendered);
    return rendered;
  }

  #renderPath(depth: number, inType: boolean): string {
    this.#checkDepth(depth);
    const tag = this.next();
    switch (tag) {
      case 67: {
        return this.identifier().text;
      }
      case 77: {
        this.optionalDisambiguator();
        this.path(depth + 1, inType);
        return `<${this.type(depth + 1)}>`;
      }
      case 88: {
        this.optionalDisambiguator();
        this.path(depth + 1, inType);
        const type = this.type(depth + 1);
        return `<${type} as ${this.path(depth + 1, inType)}>`;
      }
      case 89: {
        const type = this.type(depth + 1);
        return `<${type} as ${this.path(depth + 1, inType)}>`;
      }
      case 78: {
        const namespace = this.next();
        const upper = namespace >= 65 && namespace <= 90;
        const lower = namespace >= 97 && namespace <= 122;
        if (!upper && !lower)
          throw new DemangleFailure("v0 nested path namespace is invalid");
        const parent = this.path(depth + 1, inType);
        const ident = this.identifier();
        if (namespace === 67)
          return `${parent}::${this.#namespacedNamespace("closure", ident)}`;
        if (namespace === 83)
          return `${parent}::${this.#namespacedNamespace("shim", ident)}`;
        if (upper)
          return `${parent}::${this.#namespacedNamespace(
            String.fromCharCode(namespace),
            ident,
          )}`;
        if (ident.text.length === 0) return parent;
        return `${parent}::${ident.text}`;
      }
      case 73: {
        const inner = this.path(depth + 1, inType);
        const args: string[] = [];
        while (this.peek() !== 69) {
          if (this.peek() === undefined)
            throw new DemangleFailure("v0 generic arguments are truncated");
          if (this.peek() === 75) {
            this.#pos += 1;
            args.push(this.const(depth + 1));
          } else if (this.peek() === 76) {
            this.#pos += 1;
            args.push(
              this.#lifetimeName(this.small(this.base62(), "lifetime index")),
            );
          } else args.push(this.type(depth + 1));
        }
        this.#pos += 1;
        return `${inner}${inType ? "" : "::"}<${args.join(", ")}>`;
      }
      case 66: {
        return this.backref();
      }
      default:
        throw new DemangleFailure(
          `v0 path tag 0x${tag.toString(16)} is not supported`,
        );
    }
  }

  #namespacedNamespace(
    namespace: string,
    ident: { readonly text: string; readonly disambiguator: bigint },
  ): string {
    const name = ident.text.length === 0 ? "" : `:${ident.text}`;
    return `{${namespace}${name}#${ident.disambiguator.toString(10)}}`;
  }

  optionalDisambiguator(): void {
    if (this.peek() === 115) {
      this.#pos += 1;
      this.base62();
    }
  }

  type(depth: number): string {
    const start = this.#pos;
    const rendered = this.#renderType(depth);
    this.record(start, rendered);
    return rendered;
  }

  #renderType(depth: number): string {
    this.#checkDepth(depth);
    const tag = this.next();
    if (tag >= 97 && tag <= 122) {
      const basic = BASIC_TYPES[String.fromCharCode(tag)];
      if (basic !== undefined) return basic;
      throw new DemangleFailure(
        `v0 type tag 0x${tag.toString(16)} is not supported`,
      );
    }
    switch (tag) {
      case 65: {
        const element = this.type(depth + 1);
        return `[${element}; ${this.const(depth + 1)}]`;
      }
      case 83: {
        return `[${this.type(depth + 1)}]`;
      }
      case 84: {
        const fields: string[] = [];
        while (this.peek() !== 69) {
          if (this.peek() === undefined)
            throw new DemangleFailure("v0 tuple types are truncated");
          fields.push(this.type(depth + 1));
        }
        this.#pos += 1;
        return `(${fields.join(", ")})`;
      }
      case 82: {
        const prefix =
          this.peek() === 76 ? this.#lifetimePrefix(this.lifetime()) : "";
        return `&${prefix}${this.type(depth + 1)}`;
      }
      case 81: {
        const prefix =
          this.peek() === 76 ? this.#lifetimePrefix(this.lifetime()) : "";
        return `&mut ${prefix}${this.type(depth + 1)}`;
      }
      case 80: {
        return `*const ${this.type(depth + 1)}`;
      }
      case 79: {
        return `*mut ${this.type(depth + 1)}`;
      }
      case 70: {
        const saved = this.#binderCount;
        let binders = "";
        if (this.peek() === 71) {
          this.#pos += 1;
          binders = `for<${this.#binderList(
            this.small(this.base62() + 1n, "binder count"),
          )}> `;
        }
        const signature = this.#fnSignature(depth);
        this.#binderCount = saved;
        return `${binders}${signature}`;
      }
      case 68: {
        const saved = this.#binderCount;
        let binders = "";
        if (this.peek() === 71) {
          this.#pos += 1;
          binders = `for<${this.#binderList(
            this.small(this.base62() + 1n, "binder count"),
          )}> `;
        }
        const traits: string[] = [];
        while (this.peek() !== 69) {
          if (this.peek() === undefined)
            throw new DemangleFailure("v0 dyn bounds are truncated");
          let trait = this.path(depth + 1, true);
          const bindings: string[] = [];
          while (this.peek() === 112) {
            this.#pos += 1;
            const name = this.unqualifiedAbi();
            const isConst = this.peek() === 75;
            if (isConst) this.#pos += 1;
            const value = isConst
              ? this.const(depth + 1)
              : this.type(depth + 1);
            bindings.push(`${name} = ${value}`);
          }
          if (bindings.length > 0) trait = `${trait}<${bindings.join(", ")}>`;
          traits.push(trait);
        }
        this.#pos += 1;
        const lifetime =
          this.peek() === 76 ? this.#lifetimeSuffix(this.lifetime()) : "";
        this.#binderCount = saved;
        return `${binders}dyn ${traits.join(" + ")}${lifetime}`;
      }
      case 67:
      case 77:
      case 88:
      case 89:
      case 78:
      case 73:
      case 66: {
        this.#pos -= 1;
        return this.path(depth + 1, true);
      }
      default:
        throw new DemangleFailure(
          `v0 type tag 0x${tag.toString(16)} is not supported`,
        );
    }
  }

  #fnSignature(depth: number): string {
    let unsafe = false;
    if (this.peek() === 85) {
      unsafe = true;
      this.#pos += 1;
    }
    let abi = "";
    if (this.peek() === 75) {
      this.#pos += 1;
      if (this.peek() === 67) {
        abi = 'extern "C" ';
        this.#pos += 1;
      } else abi = `extern "${this.unqualifiedAbi()}" `;
    }
    const inputs: string[] = [];
    while (this.peek() !== 69) {
      if (this.peek() === undefined)
        throw new DemangleFailure("v0 function signature is truncated");
      inputs.push(this.type(depth + 1));
    }
    this.#pos += 1;
    const output = this.type(depth + 1);
    const returns = output === "()" ? "" : ` -> ${output}`;
    return `${unsafe ? "unsafe " : ""}${abi}fn(${inputs.join(", ")})${returns}`;
  }

  #binderList(count: number): string {
    this.#binderCount = count;
    const names: string[] = [];
    // Every lifetime name is charged against the output budget so a large
    // base-62 binder count cannot render an unbounded list.
    for (let level = 0; level < count; level += 1) {
      const name =
        level < 26 ? `'${String.fromCharCode(97 + level)}` : `'_${level + 1}`;
      this.charge(name);
      names.push(name);
    }
    return names.join(", ");
  }

  #lifetimeName(index: number): string {
    if (index === 0) return "'_";
    const level = this.#binderCount - index;
    if (level < 0 || level > 25) return `'_${index}`;
    return `'${String.fromCharCode(97 + level)}`;
  }

  #lifetimePrefix(index: number): string {
    return index === 0 ? "" : `${this.#lifetimeName(index)} `;
  }

  #lifetimeSuffix(index: number): string {
    return index === 0 ? "" : ` + ${this.#lifetimeName(index)}`;
  }

  unqualifiedAbi(): string {
    const { text } = this.#abiBytes();
    this.charge(text);
    return text;
  }

  #abiBytes(): { text: string } {
    let punycode = false;
    if (this.peek() === 117) {
      const following = this.bytes[this.#pos + 1];
      if (following !== undefined && following >= 48 && following <= 57) {
        punycode = true;
        this.#pos += 1;
      }
    }
    const length = this.decimal();
    if (this.peek() === 95) this.#pos += 1;
    if (length > this.bytes.length - this.#pos)
      throw new DemangleFailure("v0 identifier bytes exceed the input");
    const raw = this.bytes.subarray(this.#pos, this.#pos + length);
    this.#pos += length;
    try {
      const text: string = new TextDecoder("utf-8", {
        fatal: true,
      }).decode(raw);
      return { text: punycode ? decodePunycode(text) : text };
    } catch {
      throw new DemangleFailure("v0 identifier is not valid UTF-8");
    }
  }

  const(depth: number): string {
    const start = this.#pos;
    const rendered = this.#renderConst(depth);
    this.record(start, rendered);
    return rendered;
  }

  #renderConst(depth: number): string {
    this.#checkDepth(depth);
    if (this.peek() === 112) {
      this.#pos += 1;
      return "_";
    }
    if (this.peek() === 66) {
      this.#pos += 1;
      return this.backref();
    }
    const type = this.next();
    const typeChar = String.fromCharCode(type);
    const typeName = BASIC_TYPES[typeChar];
    let negative = false;
    if (this.peek() === 110) {
      negative = true;
      this.#pos += 1;
      const unsigned = UNSIGNED_CONST_TYPES.has(typeChar);
      if (unsigned)
        throw new DemangleFailure("v0 unsigned const data is not negative");
    }
    let digits = "";
    for (;;) {
      const byte = this.peek();
      if (byte === undefined)
        throw new DemangleFailure("v0 const data is truncated");
      if (byte === 95) break;
      if (!isHexDigit(byte))
        throw new DemangleFailure("v0 const data is not hexadecimal");
      digits += String.fromCharCode(byte);
      this.#pos += 1;
    }
    this.#pos += 1;
    if (digits.length === 0)
      throw new DemangleFailure("v0 const data is empty");
    if (type === 98) {
      if (negative || (digits !== "0" && digits !== "1"))
        throw new DemangleFailure("v0 boolean const data is invalid");
      return digits === "0" ? "false" : "true";
    }
    if (type === 99) {
      const codepoint = Number.parseInt(digits, 16);
      if (codepoint > 0x10_ff_ff)
        throw new DemangleFailure("v0 char const value is out of range");
      return `'${String.fromCodePoint(codepoint)}'`;
    }
    if (
      typeName !== undefined &&
      (SIGNED_CONST_TYPES.has(typeChar) || UNSIGNED_CONST_TYPES.has(typeChar))
    ) {
      if (digits.length > 39)
        throw new DemangleFailure("v0 const value exceeds 128 bits");
      const value = BigInt(`0x${digits}`);
      return (negative ? "-" : "") + value.toString(10);
    }
    throw new DemangleFailure(
      "v0 const values are only decoded for integer, boolean and character types",
    );
  }

  backref(): string {
    const target = this.small(this.base62(), "backref offset");
    const cached = this.#rendered.get(target);
    if (cached === undefined)
      throw new DemangleFailure(
        "v0 backref does not match a recorded symbol element",
      );
    this.charge(cached);
    return cached;
  }

  #checkDepth(depth: number): void {
    if (depth > MAX_PARSE_DEPTH)
      throw new DemangleFailure("v0 nesting exceeds the depth limit");
  }
}

const base62Digit = (byte: number): number | undefined => {
  if (byte >= 48 && byte <= 57) return byte - 48;
  if (byte >= 97 && byte <= 122) return byte - 87;
  if (byte >= 65 && byte <= 90) return byte - 29;
  return undefined;
};

const isHexDigit = (byte: number): boolean =>
  (byte >= 48 && byte <= 57) ||
  (byte >= 97 && byte <= 102) ||
  (byte >= 65 && byte <= 70);

const checkOutput = (value: string): string => {
  if (value.length > RUST_DEMANGLE_OUTPUT_CHARS)
    throw new DemangleFailure(
      `Demangled output exceeds the ${RUST_DEMANGLE_OUTPUT_CHARS} character limit`,
    );
  return value;
};

/**
 * Punycode decoder for v0 identifier bytes, mirroring rustc-demangle's
 * Ident decoder (RFC 3492 variant). The identifier splits at the LAST `_`:
 * standard Punycode separates the ASCII part with `-`, which cannot appear in
 * v0 symbols, so `-` is encoded (and here split) as `_`. Only lowercase
 * alpha and digit digits are decoded, matching rustc-demangle's case-sensitive
 * digit alphabet.
 */
const decodePunycode = (encoded: string): string => {
  const delimiter = encoded.lastIndexOf("_");
  const basicPart = delimiter >= 0 ? encoded.slice(0, delimiter) : "";
  const digits = delimiter >= 0 ? encoded.slice(delimiter + 1) : encoded;
  let base = basicPart;
  let char = 0x80;
  let insertAt = 0;
  let bias = 72;
  let damp = 700;
  let cursor = 0;
  for (;;) {
    // Read one delta value.
    let delta = 0;
    let weight = 1;
    let k = 0;
    for (;;) {
      if (cursor >= digits.length)
        throw new DemangleFailure("v0 punycode encoding is truncated");
      k += 36;
      const code = digits.charCodeAt(cursor);
      cursor += 1;
      let digit: number;
      if (code >= 97 && code <= 122) digit = code - 97;
      else if (code >= 48 && code <= 57) digit = 26 + (code - 48);
      else throw new DemangleFailure("v0 punycode digit is invalid");
      delta += digit * weight;
      if (delta > Number.MAX_SAFE_INTEGER)
        throw new DemangleFailure("v0 punycode value exceeds its safe range");
      const threshold = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < threshold) break;
      weight *= 36 - threshold;
    }
    // Compute the new insert position and character.
    const length = base.length + 1;
    insertAt += delta;
    char += Math.floor(insertAt / length);
    insertAt %= length;
    if (char > 0x10_ff_ff)
      throw new DemangleFailure("v0 punycode codepoint is out of range");
    base =
      base.slice(0, insertAt) +
      String.fromCodePoint(char) +
      base.slice(insertAt);
    insertAt += 1;
    if (cursor >= digits.length) return base;
    // Perform bias adaptation (rustc-demangle's damped first round).
    delta = Math.floor(delta / damp);
    damp = 2;
    delta += Math.floor(delta / base.length);
    let adapted = 0;
    while (delta > ((36 - 1) * 26) / 2) {
      delta = Math.floor(delta / 35);
      adapted += 36;
    }
    bias = adapted + Math.floor((36 * delta) / (delta + 38));
  }
};

const adapt = (delta: number, first: boolean, numchars: number): number => {
  let value = first ? Math.floor(delta / 700) : Math.floor(delta / 2);
  value += Math.floor(value / numchars);
  let divisions = 0;
  while (value > 455) {
    value = Math.floor(value / 35);
    divisions += 36;
  }
  return divisions + Math.floor((36 * value) / (value + 38));
};

const demangleV0 = (mangled: string): string => {
  let body = mangled.replace(/^_+/, "");
  if (!body.startsWith("R"))
    throw new DemangleFailure("v0 symbol prefix is missing");
  body = body.slice(1);
  while (/^[0-9]/u.test(body)) body = body.slice(1);
  const parser = new V0Parser(Buffer.from(body, "utf8"));
  const name = parser.path(0);
  if (!parser.done) {
    if (parser.peek() === 46 || parser.peek() === 36) return checkOutput(name);
    if (!PATH_TAGS.includes(parser.peek() ?? -1))
      throw new DemangleFailure("v0 symbol has unexpected trailing bytes");
    parser.path(0);
    if (!parser.done) {
      const second = parser.peek();
      if (second !== 46 && second !== 36)
        throw new DemangleFailure("v0 symbol has unexpected trailing bytes");
    }
  }
  return checkOutput(name);
};
