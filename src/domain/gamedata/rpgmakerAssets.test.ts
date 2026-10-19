import { describe, expect, it } from "vitest";

import {
  RPGMAKER_FAKE_HEADER,
  buildPlainOgg,
  buildPlainPng,
  buildRpgmakerEncryptedOgg,
  buildRpgmakerEncryptedPng,
  buildRpgmakerEncryptedUnknown,
} from "./gamedataFixtures.js";
import { classifyRpgmakerHead } from "./rpgmakerAssets.js";

describe("classifyRpgmakerHead", () => {
  it("detects the RPGMV fake header over the restored PNG magic", () => {
    const bytes = buildRpgmakerEncryptedPng();
    const classified = classifyRpgmakerHead(
      bytes.length,
      bytes.subarray(0, 24),
    );
    expect(classified.prefix_present).toBe(true);
    expect(classified.prefix_hex).toBe(RPGMAKER_FAKE_HEADER.toString("hex"));
    expect(classified.encrypted_kind_guess).toBe("png");
    expect(classified.plain_kind).toBe("unknown");
    expect(classified.following_hex).toBe(
      bytes.subarray(16, 24).toString("hex"),
    );
  });

  it("guesses ogg when the fake header covers an OggS magic", () => {
    const bytes = buildRpgmakerEncryptedOgg();
    const classified = classifyRpgmakerHead(
      bytes.length,
      bytes.subarray(0, 24),
    );
    expect(classified.prefix_present).toBe(true);
    expect(classified.encrypted_kind_guess).toBe("ogg");
  });

  it("keeps unrecognized continuations unknown rather than guessing", () => {
    const bytes = buildRpgmakerEncryptedUnknown();
    const classified = classifyRpgmakerHead(
      bytes.length,
      bytes.subarray(0, 24),
    );
    expect(classified.prefix_present).toBe(true);
    expect(classified.encrypted_kind_guess).toBe("unknown");
  });

  it("classifies plain PNG and Ogg signatures for comparison", () => {
    expect(
      classifyRpgmakerHead(32, buildPlainPng().subarray(0, 24)).plain_kind,
    ).toBe("png");
    expect(
      classifyRpgmakerHead(32, buildPlainOgg().subarray(0, 24)).plain_kind,
    ).toBe("ogg");
    const plain = classifyRpgmakerHead(32, buildPlainPng().subarray(0, 24));
    expect(plain.prefix_present).toBe(false);
    expect(plain.prefix_hex).toBeNull();
    expect(plain.encrypted_kind_guess).toBe("unknown");
  });

  it("reports insufficient bytes instead of guessing on truncated heads", () => {
    const classified = classifyRpgmakerHead(
      16,
      Buffer.concat([RPGMAKER_FAKE_HEADER]),
    );
    expect(classified.prefix_present).toBe(true);
    expect(classified.encrypted_kind_guess).toBe("insufficient_bytes");
    expect(classified.following_hex).toBeNull();
  });
});
