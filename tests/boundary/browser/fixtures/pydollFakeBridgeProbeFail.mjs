#!/usr/bin/env node
// Offline pydoll-bridge stand-in: the probe reports pydoll as missing.

if (process.argv.includes("--check")) {
  process.stdout.write(
    "[rea-pydoll-bridge] ModuleNotFoundError: No module named 'pydoll'\n",
  );
  process.stderr.write(
    "[rea-pydoll-bridge] ModuleNotFoundError: No module named 'pydoll'\n",
  );
  process.exit(3);
}
process.stdout.write("--check is the only supported invocation\n");
process.exit(2);
