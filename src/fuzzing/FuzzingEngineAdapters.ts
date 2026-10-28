import type { FuzzingEngine } from "../domain/fuzzing/fuzzingEngine.js";
import { AflFridaAdapter } from "./AflFridaAdapter.js";
import { JackalopeAdapter } from "./JackalopeAdapter.js";
import { LibFuzzerAdapter } from "./LibFuzzerAdapter.js";
import type { FuzzingEngineAdapter } from "./FuzzingEngineAdapter.js";

const ADAPTERS: Readonly<Record<FuzzingEngine, FuzzingEngineAdapter>> = {
  libfuzzer: new LibFuzzerAdapter(),
  aflpp_frida: new AflFridaAdapter(),
  jackalope: new JackalopeAdapter(),
};

/** Resolve the one adapter that owns an engine's argv and artifacts. */
export const fuzzingEngineAdapter = (
  engine: FuzzingEngine,
): FuzzingEngineAdapter => ADAPTERS[engine];
