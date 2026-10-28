import { describe, expect, it } from "vitest";

import {
  openBinaryInputSchema,
  runLabVmCommandInputSchema,
  startLabVmInputSchema,
  stopLabVmInputSchema,
} from "./sessionLifecycleInputs.js";

describe("open_binary raw-binary input contract", () => {
  it("accepts header detection without architecture", () => {
    expect(
      openBinaryInputSchema.safeParse({ path: "/tmp/fixture.bin" }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/legacy.com",
        format: "dos-com",
      }).success,
    ).toBe(true);
  });
  it("accepts raw-binary with architecture and entry", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(true);
  });
  it("rejects raw-binary without architecture or entry", () => {
    const parsed = openBinaryInputSchema.safeParse({
      path: "/tmp/ecu.bin",
      format: "raw-binary",
    });
    expect(parsed.success).toBe(false);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
      }).success,
    ).toBe(false);
  });
  it("rejects architecture without format=raw-binary", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(false);
  });
});

describe("lab VM session input contracts", () => {
  it("accepts an absolute workspace and a UUID session identity", () => {
    expect(
      startLabVmInputSchema.safeParse({ workspace_path: "/tmp/lab" }).success,
    ).toBe(true);
    expect(
      runLabVmCommandInputSchema.safeParse({
        session_id: "00000000-0000-4000-8000-000000000001",
        command: "uname -a",
      }).success,
    ).toBe(true);
    expect(
      stopLabVmInputSchema.safeParse({
        session_id: "00000000-0000-4000-8000-000000000001",
      }).success,
    ).toBe(true);
  });

  it("rejects a relative workspace, a non-UUID session, and NUL bytes", () => {
    expect(
      startLabVmInputSchema.safeParse({ workspace_path: "lab" }).success,
    ).toBe(false);
    expect(
      stopLabVmInputSchema.safeParse({ session_id: "lab-vm-1" }).success,
    ).toBe(false);
    expect(
      runLabVmCommandInputSchema.safeParse({
        session_id: "00000000-0000-4000-8000-000000000001",
        command: "echo\u0000",
      }).success,
    ).toBe(false);
  });

  it("keeps the guest command closed and bounded", () => {
    expect(
      runLabVmCommandInputSchema.safeParse({
        session_id: "00000000-0000-4000-8000-000000000001",
        command: "true",
        command_timeout_ms: 0,
      }).success,
    ).toBe(false);
    expect(
      runLabVmCommandInputSchema.safeParse({
        session_id: "00000000-0000-4000-8000-000000000001",
        command: "true",
        extra: true,
      }).success,
    ).toBe(false);
  });
});
