import { describe, expect, it } from "vitest";

import {
  captureInputSchemas,
  captureRequestSchema,
  CAPTURE_COMMAND_REMEDIATION,
  CAPTURE_OPERATION,
  PACKET_CAPTURE_COMMAND_ENV,
  type CaptureRequest,
} from "./CaptureAnalysis.js";

const VALID_INPUT = {
  output_path: "/tmp/capture-radio.pcap",
  duration_seconds: 5,
  authorize_capture: true,
} as const;

describe(CAPTURE_OPERATION, () => {
  it("applies defaults and admits a minimal valid input", () => {
    const parsed = captureRequestSchema.parse({
      operation: CAPTURE_OPERATION,
      input: {
        output_path: "/tmp/capture-radio.pcap",
        authorize_capture: true,
      },
    });
    expect(parsed.input).toEqual({
      output_path: "/tmp/capture-radio.pcap",
      duration_seconds: 10,
      authorize_capture: true,
    });
  });

  it("admits an optional command override and a .pcapng output path", () => {
    const parsed = captureRequestSchema.parse({
      operation: CAPTURE_OPERATION,
      input: {
        output_path: "/tmp/window.pcapng",
        duration_seconds: 60,
        authorize_capture: true,
        command: "/caller/capture-wrapper",
      },
    });
    expect(parsed).toMatchObject({
      input: { command: "/caller/capture-wrapper" },
    });
  });

  it("rejects relative output paths", () => {
    const parsed = captureRequestSchema.safeParse({
      operation: CAPTURE_OPERATION,
      input: { ...VALID_INPUT, output_path: "relative/capture.pcap" },
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects output paths that do not end in .pcap or .pcapng", () => {
    for (const suffix of [".dat", "", ".PCAP"]) {
      const parsed = captureRequestSchema.safeParse({
        operation: CAPTURE_OPERATION,
        input: { ...VALID_INPUT, output_path: `/tmp/capture${suffix}` },
      });
      expect(parsed.success).toBe(false);
    }
  });

  it("rejects missing or false authorization", () => {
    const missing = captureRequestSchema.safeParse({
      operation: CAPTURE_OPERATION,
      input: { output_path: "/tmp/capture-radio.pcap" },
    });
    expect(missing.success).toBe(false);
    const literal = captureInputSchemas[CAPTURE_OPERATION].safeParse({
      ...VALID_INPUT,
      authorize_capture: false,
    });
    expect(literal.success).toBe(false);
  });

  it("bounds the duration window at one second through sixty seconds", () => {
    for (const duration of [0, 61, 5.5]) {
      const parsed = captureRequestSchema.safeParse({
        operation: CAPTURE_OPERATION,
        input: { ...VALID_INPUT, duration_seconds: duration },
      });
      expect(parsed.success).toBe(false);
    }
  });

  it("rejects unknown arguments and non-absolute out-of-schema shapes", () => {
    const parsed = captureRequestSchema.safeParse({
      operation: CAPTURE_OPERATION,
      input: { ...VALID_INPUT, capture_seconds: 5 },
    });
    expect(parsed.success).toBe(false);
  });

  it("keeps request typing correlated with the discriminated union", () => {
    const request: CaptureRequest = {
      operation: CAPTURE_OPERATION,
      input: {
        output_path: "/tmp/capture-radio.pcap",
        duration_seconds: 1,
        authorize_capture: true,
      },
    };
    expect(request.operation).toBe(CAPTURE_OPERATION);
  });

  it("names the caller-supplied capture command env in the remediation", () => {
    expect(PACKET_CAPTURE_COMMAND_ENV).toBe("REA_PACKET_CAPTURE_COMMAND");
    expect(CAPTURE_COMMAND_REMEDIATION).toContain("REA_PACKET_CAPTURE_COMMAND");
    expect(CAPTURE_COMMAND_REMEDIATION).toContain("never installs");
    expect(CAPTURE_COMMAND_REMEDIATION).toContain("never elevates");
  });
});
