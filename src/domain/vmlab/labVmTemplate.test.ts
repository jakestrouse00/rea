import { describe, expect, it } from "vitest";

import { LabVmTemplateRejection, labVmTemplate } from "./labVmTemplate.js";

describe("lab VM template", () => {
  it("selects the vz driver, Rosetta translation, and one writable mount", () => {
    expect(labVmTemplate("/tmp/rea-lab")).toBe(
      [
        "# REA lab VM template; generated per start and deleted with the session.",
        "vmType: vz",
        "rosetta:",
        "  enabled: true",
        "  binfmt: true",
        "mounts:",
        '  - location: "/tmp/rea-lab"',
        '    mountPoint: "/workspace"',
        "    writable: true",
        "",
      ].join("\n"),
    );
  });

  it("never adds a second host mount", () => {
    const template = labVmTemplate("/tmp/a");
    expect(template.match(/location: /gu)).toHaveLength(1);
    expect(template).not.toContain("~");
  });

  it("escapes a representable path and refuses an unrepresentable one", () => {
    expect(labVmTemplate('/tmp/we"ird')).toContain('location: "/tmp/we\\"ird"');
    expect(() => labVmTemplate("/tmp/a\u0001b")).toThrow(
      LabVmTemplateRejection,
    );
  });
});
