import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

/** Stand-in for one fuzzing engine, driven only by a scenario file. */
const scenarioPath = process.env.REA_FAKE_ENGINE_SCENARIO;
if (scenarioPath === undefined) {
  process.stderr.write("REA_FAKE_ENGINE_SCENARIO is unset\n");
  process.exit(2);
}
const scenario = JSON.parse(readFileSync(scenarioPath, "utf8"));
const argv = process.argv.slice(2);

const isFile = (value) => {
  try {
    return statSync(value).isFile();
  } catch {
    return false;
  }
};

const optionValue = (name) => {
  const index = argv.indexOf(name);
  return index === -1 ? null : (argv[index + 1] ?? null);
};

const writeArtifacts = (directory) => {
  if (directory === null) return;
  mkdirSync(directory, { recursive: true });
  for (const artifact of scenario.artifacts ?? []) {
    writeFileSync(join(directory, artifact.name), artifact.content ?? "AAAA");
  }
  if (scenario.statsFile !== undefined) {
    const lines = Object.entries(scenario.statsFile).map(
      ([key, value]) => `${key}: ${String(value)}`,
    );
    writeFileSync(
      join(directory, "..", "fuzzer_stats"),
      `${lines.join("\n")}\n`,
    );
  }
};

const writeReport = (basename) => {
  const reports = scenario.reports?.[basename];
  const bodies = Array.isArray(reports) ? reports : [];
  if (bodies.length === 0) return null;
  const counterPath = scenario.counterPath;
  let counter = 0;
  if (counterPath !== undefined && existsSync(counterPath))
    counter = Number(readFileSync(counterPath, "utf8")) || 0;
  if (counterPath !== undefined)
    writeFileSync(counterPath, String(counter + 1));
  // A candidate may crash only in its first N reproductions.
  if (counter >= (scenario.reproduceCrashes ?? Number.POSITIVE_INFINITY))
    return null;
  return bodies[counter % bodies.length];
};

const reproduction = argv.length === 1 && isFile(argv[0]);

if (reproduction) {
  const body = writeReport(argv[0].split(/[\\/]/u).pop() ?? "");
  if (body === null) process.exit(scenario.reproduceMissExitCode ?? 0);
  process.stderr.write(body);
  process.exit(scenario.reproduceExitCode ?? 42);
}

const artifactPrefix = argv.find((value) =>
  value.startsWith("-artifact_prefix="),
);
const outputDirectory = optionValue("-o");
writeArtifacts(
  scenario.engine === "afl"
    ? outputDirectory === null
      ? null
      : join(outputDirectory, "default", "crashes")
    : artifactPrefix !== undefined
      ? artifactPrefix.slice("-artifact_prefix=".length).replace(/\/$/u, "")
      : outputDirectory,
);

const pause = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

if (scenario.ignoreTerm !== true)
  process.on("SIGTERM", () => {
    process.exit(0);
  });

for (const line of scenario.stats ?? []) {
  process.stdout.write(`${line}\n`);
  if ((scenario.delayMs ?? 0) > 0) await pause(scenario.delayMs);
}
if ((scenario.holdMs ?? 0) > 0) await pause(scenario.holdMs);
process.exit(scenario.exitCode ?? 0);
