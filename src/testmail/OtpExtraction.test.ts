import { describe, expect, it } from "vitest";

import {
  extractMagicLinks,
  extractVerificationCodes,
} from "./OtpExtraction.js";

describe("extractVerificationCodes", () => {
  it("extracts a 6-digit code beside an English keyword", () => {
    expect(
      extractVerificationCodes(
        "Welcome!\r\nYour verification code is 582914.\r\nIt expires in 10 minutes.",
      ),
    ).toEqual(["582914"]);
  });

  it("extracts an alphanumeric code beside a keyword", () => {
    expect(
      extractVerificationCodes("Use the confirmation code AB12CD to verify"),
    ).toEqual(["AB12CD"]);
  });

  it("scopes keyword lines when any are present", () => {
    const body = [
      "Order 44551 shipped via USPS today.",
      "Your one-time code is 738412",
      "This mailbox is disposable and will expire.",
    ].join("\n");
    expect(extractVerificationCodes(body)).toEqual(["738412"]);
  });

  it("falls back to the whole body when no keyword line exists", () => {
    expect(extractVerificationCodes("Your access token: 554403")).toEqual([
      "554403",
    ]);
  });

  it("extracts codes beside Chinese and German labels", () => {
    const german = extractVerificationCodes(
      "Bitte bestätigen Sie mit dem Code 919283.",
    );
    const chinese = extractVerificationCodes(
      "您的验证码是 662041，5分钟内有效。",
    );
    expect(german).toEqual(["919283"]);
    expect(chinese).toEqual(["662041"]);
  });

  it("keeps 4-digit minimum and drops longer digit runs", () => {
    expect(extractVerificationCodes("code 123 is too short")).toEqual([]);
    expect(
      extractVerificationCodes("reference 123456789012345 is not a code"),
    ).toEqual([]);
  });
});

describe("extractMagicLinks", () => {
  it("extracts HTTPS links and trims trailing punctuation", () => {
    const body = [
      "Confirm here: https://signup.example.com/verify?token=abc123.",
      "Plain http link http://insecure.example.test/",
    ].join("\n");
    expect(extractMagicLinks(body)).toEqual([
      "https://signup.example.com/verify?token=abc123",
      "http://insecure.example.test/",
    ]);
  });

  it("does not include angle-bracket markup in links", () => {
    expect(
      extractMagicLinks('<a href="https://mail.example.com/r/9a8b7c">Go</a>'),
    ).toEqual(["https://mail.example.com/r/9a8b7c"]);
  });

  it("returns empty for no links", () => {
    expect(extractMagicLinks("no links here")).toEqual([]);
  });
});
