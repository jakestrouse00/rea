import { describe, expect, it } from "vitest";

import { parseBleScanLines } from "./BleScanAnalysis.js";

describe("parseBleScanLines", () => {
  it("parses the discovered and updated advertisement rows", () => {
    const ran = parseBleScanLines(
      [
        '{"event":"discovered","ts":"2026-10-27T12:00:00.000Z","address_or_uuid":"D2FC1D34-9BA1-4B0D-A6BE-C7E4F1C8A211","name":"Tile Mate","rssi":-62,"connectable":true,"manufacturer_hex":"4c0002151234","service_uuids":["180F"],"flags_description":null}',
        '{"event":"updated","ts":"2026-10-27T12:00:01.250Z","address_or_uuid":"D2FC1D34-9BA1-4B0D-A6BE-C7E4F1C8A211","name":"Tile Mate","rssi":-71,"connectable":false,"manufacturer_hex":null,"service_uuids":[],"flags_description":null}',
      ].join("\n"),
    );
    expect(ran.unparsedLines).toEqual([]);
    expect(ran.items).toEqual([
      {
        event: "discovered",
        ts: "2026-10-27T12:00:00.000Z",
        address_or_uuid: "D2FC1D34-9BA1-4B0D-A6BE-C7E4F1C8A211",
        name: "Tile Mate",
        rssi: -62,
        connectable: true,
        manufacturer_hex: "4c0002151234",
        service_uuids: ["180F"],
        raw: '{"event":"discovered","ts":"2026-10-27T12:00:00.000Z","address_or_uuid":"D2FC1D34-9BA1-4B0D-A6BE-C7E4F1C8A211","name":"Tile Mate","rssi":-62,"connectable":true,"manufacturer_hex":"4c0002151234","service_uuids":["180F"],"flags_description":null}',
      },
      {
        event: "updated",
        ts: "2026-10-27T12:00:01.250Z",
        address_or_uuid: "D2FC1D34-9BA1-4B0D-A6BE-C7E4F1C8A211",
        name: "Tile Mate",
        rssi: -71,
        connectable: false,
        manufacturer_hex: null,
        service_uuids: [],
        raw: '{"event":"updated","ts":"2026-10-27T12:00:01.250Z","address_or_uuid":"D2FC1D34-9BA1-4B0D-A6BE-C7E4F1C8A211","name":"Tile Mate","rssi":-71,"connectable":false,"manufacturer_hex":null,"service_uuids":[],"flags_description":null}',
      },
    ]);
  });

  it("keeps unknowns null and service_uuids empty without inventing values", () => {
    const line =
      '{"event":"discovered","address_or_uuid":"EA0EA98B-5CC0-4A7F-8D4B-2C4EF7F4E1D2"}';
    const ran = parseBleScanLines(line);
    expect(ran.unparsedLines).toEqual([]);
    expect(ran.items[0]).toEqual({
      event: "discovered",
      ts: null,
      address_or_uuid: "EA0EA98B-5CC0-4A7F-8D4B-2C4EF7F4E1D2",
      name: null,
      rssi: null,
      connectable: null,
      manufacturer_hex: null,
      service_uuids: [],
      raw: line,
    });
  });

  it("preserves non-JSON and wrong-event rows verbatim", () => {
    const ran = parseBleScanLines(
      [
        '{"event":"discovered","address_or_uuid":"A1"}',
        "ble-scan: unexpected crash trace",
        '{"event":"authorization_denied"}',
        "[1,2]",
        "",
      ].join("\n"),
    );
    expect(ran.items.map((row) => row.address_or_uuid)).toEqual(["A1"]);
    expect(ran.unparsedLines).toEqual([
      "ble-scan: unexpected crash trace",
      '{"event":"authorization_denied"}',
      "[1,2]",
    ]);
  });

  it("ignores non-entry JSON shapes and non-string filter entries", () => {
    const ran = parseBleScanLines(
      [
        '"plain string"',
        "123",
        '{"event":"updated","address_or_uuid":"B2","rssi":"-40","service_uuids":["180F",5,null]}',
      ].join("\n"),
    );
    expect(ran.unparsedLines).toEqual(['"plain string"', "123"]);
    expect(ran.items[0]?.rssi).toBeNull();
    expect(ran.items[0]?.service_uuids).toEqual(["180F"]);
  });
});
