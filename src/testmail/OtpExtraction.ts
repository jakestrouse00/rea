/**
 * Verification-artifact extraction from mail bodies.
 *
 * Adapted from the MIT-licensed tossinbox project
 * (github.com/mohamed-khairy-5i/tossinbox, src/core/otp.ts): keyword-line
 * scoping across i18n labels, then code-shaped token matching. Extended with
 * magic-link extraction for one-time sign-in URLs.
 */

const codeKeywords = [
  // English
  "code",
  "verification",
  "verify",
  "otp",
  "passcode",
  "one-time",
  "one time",
  "2fa",
  "twofactor",
  "two-factor",
  // French
  "code de vérification",
  "vérification",
  "votre code",
  // Spanish / Portuguese / Italian
  "código",
  "verificación",
  "código de verificação",
  "verificação",
  "codice",
  "verifica",
  // German
  "code",
  "bestätigungscode",
  "verifizierung",
  // Russian
  "код",
  "подтверждение",
  "верификация",
  // Turkish
  "doğrulama",
  "onay kodu",
  // Arabic
  "رمز التحقق",
  "رمز",
  // Chinese / Japanese / Korean
  "验证码",
  "校验码",
  "确认码",
  "認証コード",
  "確認コード",
  "인증번호",
] as const;

/** \d{4,8} digits, or 5-8 chars of mixed letters and digits, each fully delimited. */
const CODE_TOKEN_PATTERN =
  /(?<!\d)\d{4,8}(?!\d)|(?<![A-Za-z\d])(?=[\d]*[A-Za-z])(?=[A-Za-z]*[\d])[A-Za-z\d]{5,8}(?![A-Za-z\d])/g;

const URL_PATTERN = /https?:\/\/[^\s<>"'()[\]{}]+/g;

/** Trailing punctuation and common tracking suffixes stripped from URLs. */
const URL_TRAILING_TRIM = /[.,;:!?)\]]+$/;

const keywordScope = (lines: readonly string[]): string => {
  const scoped = lines.filter((line) =>
    codeKeywords.some((keyword) =>
      line.toLowerCase().includes(keyword.toLowerCase()),
    ),
  );
  return scoped.length === 0 ? lines.join("\n") : scoped.join("\n");
};

const normalizeCodeToken = (token: string): string =>
  token.replace(/[^A-Za-z\d]/g, "");

const extractCodes = (body: string): string[] => {
  const text = body
    .replace(/<[^>]+>/g, " ")
    .replace(/\r\n/g, "\n")
    .replace(/\s+$/gm, "");
  const lines = text.split("\n").filter((line) => line.trim().length > 0);
  const scope = keywordScope(lines);
  const found = new Set<string>();
  for (const match of scope.matchAll(CODE_TOKEN_PATTERN)) {
    const normalized = normalizeCodeToken(match[0] ?? "");
    if (normalized.length >= 4 && normalized.length <= 8) found.add(normalized);
  }
  return [...found];
};

const extractLinks = (body: string): string[] => {
  const found = new Set<string>();
  for (const match of body.matchAll(URL_PATTERN)) {
    const url = (match[0] ?? "").replace(URL_TRAILING_TRIM, "");
    if (url.length > 0) found.add(url);
  }
  return [...found];
};

/** Short verification codes from a plain-text or HTML mail body. */
export const extractVerificationCodes = (body: string): readonly string[] =>
  extractCodes(body);

/** Sign-in or verification URLs from a mail body, in first-seen order. */
export const extractMagicLinks = (body: string): readonly string[] =>
  extractLinks(body);
