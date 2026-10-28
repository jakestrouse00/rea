import { benchTaskRequestSchema } from "../../domain/bench/benchTask.js";

/** Run one caller-supplied containerized benchmark task in a lab VM. */
export const runBenchTaskInputSchema = benchTaskRequestSchema;
