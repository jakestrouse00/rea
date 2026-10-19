#!/usr/bin/env node
// Offline pydoll-bridge stand-in: passes the probe, then breaks the real
// startup advertisement so the parent's spawn path is exercised.

const ADVERTISING = {
  advertising: {
    protocol: 1,
    pydoll_version: "3.0.0-fake",
    capabilities: {
      emulation: true,
      keyboard: true,
      select_option: true,
      downloads: false,
      popups: false,
      workers: false,
    },
  },
};

if (process.argv.includes("--check")) {
  process.stdout.write(`${JSON.stringify(ADVERTISING)}\n`);
  process.exit(0);
}
process.stdout.write("not json at all\n");
setTimeout(() => process.exit(1), 5_000);
