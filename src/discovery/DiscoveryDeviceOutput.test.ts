import { describe, expect, it } from "vitest";

import {
  cidrCandidates,
  parseArpOutput,
  parseBlueutilInquiry,
  parseBluetoothTree,
  parseBrowseOutput,
  parseNdpOutput,
  parsePingLatencyMs,
  parseUsbTree,
} from "./DiscoveryDeviceOutput.js";

describe("parseArpOutput", () => {
  it("parses complete and incomplete rows", () => {
    const ran = parseArpOutput(
      [
        "? (192.168.1.1) at a4:83:e7:12:34:56 on en0 ifscope [ethernet]",
        "? (192.168.1.64) at f0:18:98:aa:bb:cc on en0 ifscope permanent [ethernet]",
        "? (10.0.0.5) at (incomplete) on en0 ifscope [ethernet]",
        "",
      ].join("\n"),
    );
    expect(ran.unparsedLines).toEqual([]);
    expect(ran.items).toEqual([
      {
        family: "ipv4",
        ip: "192.168.1.1",
        mac: "a4:83:e7:12:34:56",
        interface: "en0",
        state: "ifscope [ethernet]",
        permanent: false,
      },
      {
        family: "ipv4",
        ip: "192.168.1.64",
        mac: "f0:18:98:aa:bb:cc",
        interface: "en0",
        state: "ifscope permanent [ethernet]",
        permanent: true,
      },
      {
        family: "ipv4",
        ip: "10.0.0.5",
        mac: null,
        interface: "en0",
        state: "ifscope [ethernet]",
        permanent: null,
      },
    ]);
  });

  it("preserves unrecognizable rows verbatim", () => {
    const ran = parseArpOutput("garbage row without structure");
    expect(ran.items).toEqual([]);
    expect(ran.unparsedLines).toEqual(["garbage row without structure"]);
  });
});

describe("parseNdpOutput", () => {
  it("parses rows with and without a link-layer address", () => {
    const ran = parseNdpOutput(
      [
        "Neighbor                             Linklayer Address  Netif Expire    S Flags",
        "fe80::1%en0                          a4:83:e7:12:34:56  en0   23s       R",
        "ff02::2%en0                          (incomplete)       en0   permanent R",
        "",
      ].join("\n"),
    );
    expect(ran.unparsedLines).toEqual([]);
    expect(ran.items[0]).toEqual({
      family: "ipv6",
      ip: "fe80::1",
      mac: "a4:83:e7:12:34:56",
      interface: "en0",
      state: "R",
      permanent: false,
    });
    expect(ran.items[1]?.mac).toBeNull();
    expect(ran.items[1]?.permanent).toBe(true);
  });

  it("reports rows whose first token is not an address as unparsed", () => {
    const ran = parseNdpOutput("garbage row");
    expect(ran.items).toEqual([]);
    expect(ran.unparsedLines).toEqual(["garbage row"]);
  });
});

describe("parseBrowseOutput", () => {
  it("collects meta-browse service types", () => {
    const ran = parseBrowseOutput(
      [
        "Browsing for _services._dns-sd._udp.local.",
        " DATE: ---Mon 27 Oct 2026---",
        " 5:31:00.000  Add  2  5  local.          _ipp._tcp.",
        " 5:31:00.100  Add  2  5  local.          _sftp-ssh._tcp.",
      ].join("\n"),
      "meta",
    );
    expect(ran.types.map((type) => type.service_type)).toEqual([
      "_ipp._tcp.",
      "_sftp-ssh._tcp.",
    ]);
    expect(ran.types.every((type) => type.instances.length === 0)).toBe(true);
    expect(ran.unparsedLines).toHaveLength(2);
  });

  it("collects instances and preserves prior types on empty windows", () => {
    const prior = parseBrowseOutput(
      " 5:31:00.000  Add  2  5  local.  _ipp._tcp.",
      "meta",
    ).types;
    const ran = parseBrowseOutput(
      [
        "Browsing for _ipp._tcp.local.",
        " 5:31:03.000  Add  2  5  local.  _ipp._tcp.local.  Office Printer",
        " 5:31:03.050  Add  2  3  local.  _ipp._tcp.local.  Downstairs Copier",
      ].join("\n"),
      "instances",
      prior,
    );
    expect(ran.types).toHaveLength(1);
    expect(ran.types[0]?.service_type).toBe("_ipp._tcp.");
    expect(ran.types[0]?.instances[0]?.interface_index).toBe("5");
    expect(ran.types[0]?.instances.map((row) => row.instance)).toEqual([
      "Office Printer",
      "Downstairs Copier",
    ]);
  });
});

describe("parseUsbTree", () => {
  it("flattens nested hub items into device rows", () => {
    const parsed = parseUsbTree({
      SPUSBDataType: [
        {
          _name: "USB31Bus",
          items: [
            {
              _name: "USB 10/100/1000 LAN",
              vendor_id: "usbvid_0b95",
              product_id: "usbpid_1790",
              serial_num: "000000001",
            },
            {
              _name: "Hub",
              items: [{ _name: "iPhone", serial_num: "abc123" }],
            },
          ],
        },
      ],
    });
    expect(parsed.items).toHaveLength(4);
    expect(parsed.items[0]?.name).toBe("USB31Bus");
    expect(parsed.items[1]?.name).toBe("USB 10/100/1000 LAN");
    expect(parsed.items[1]?.vendor_id).toBe("usbvid_0b95");
    expect(parsed.items[2]?.name).toBe("Hub");
    expect(parsed.items[3]?.serial_num).toBe("abc123");
    expect(parsed.unparsedLines).toEqual([]);
  });
});

describe("parseBluetoothTree", () => {
  it("parses device rows with connected metadata", () => {
    const parsed = parseBluetoothTree({
      SPBluetoothDataType: [
        {
          _name: "BluetoothInformation",
          paired_devices: [
            {
              device_address: "04-5C-6C-11-22-33",
              device_connected: "attributeBool|Yes",
              device_majorType: "Audio",
              device_minorType: "Headphones",
              device_productLabel: "Studio Buds",
              _name: "Studio Buds",
            },
          ],
        },
      ],
    });
    expect(parsed.items).toHaveLength(1);
    expect(parsed.items[0]).toMatchObject({
      name: "Studio Buds",
      address: "04-5C-6C-11-22-33",
      connected: true,
      major_type: "Audio",
      minor_type: "Headphones",
    });
  });
});

describe("parseBlueutilInquiry", () => {
  it("extracts address and name, preserving raw rows", () => {
    const ran = parseBlueutilInquiry(
      [
        "address: 8C-1D-96-AA-BB-CC name: 'TV Remote' not connected",
        'address: D0:03:05:11:22:33 name: "Speaker" not connected',
        "unrecognizable line",
      ].join("\n"),
    );
    expect(ran.items).toHaveLength(2);
    expect(ran.items[0]).toMatchObject({
      address: "8c-1d-96-aa-bb-cc",
      name: "TV Remote",
      raw: "address: 8C-1D-96-AA-BB-CC name: 'TV Remote' not connected",
    });
    expect(ran.items[1]?.name).toBe("Speaker");
    expect(ran.unparsedLines).toEqual(["unrecognizable line"]);
  });
});

describe("parsePingLatencyMs", () => {
  it("extracts reply latency", () => {
    expect(
      parsePingLatencyMs(
        "64 bytes from 192.168.1.1: icmp_seq=0 ttl=57 time=12.345 ms",
      ),
    ).toBe(12.345);
    expect(parsePingLatencyMs("Request timeout for icmp_seq 0")).toBeNull();
  });
});

describe("cidrCandidates", () => {
  it("enumerates a /24 excluding network and broadcast", () => {
    const ran = cidrCandidates("192.168.1.0/24");
    expect(ran.ok).toBe(true);
    expect(ran.hosts).toHaveLength(254);
    expect(ran.hosts[0]).toBe("192.168.1.1");
    expect(ran.hosts.at(-1)).toBe("192.168.1.254");
    expect(ran.hosts.includes("192.168.1.0")).toBe(false);
    expect(ran.hosts.includes("192.168.1.255")).toBe(false);
  });

  it("bounds a /22 to 1022 hosts and rejects non-network addresses", () => {
    expect(cidrCandidates("10.0.0.0/22").hosts).toHaveLength(1022);
    const rejected = cidrCandidates("192.168.1.5/24");
    expect(rejected.ok).toBe(false);
    expect(rejected.reason).toContain("network address");
  });
});
