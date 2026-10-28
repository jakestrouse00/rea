import {
  findPathsToTargetInputSchema,
  findPathsToTargetResultSchema,
  recoverControlFlowAngrInputSchema,
  recoverControlFlowAngrResultSchema,
  runSymbolicFunctionExplorationInputSchema,
  runSymbolicFunctionExplorationResultSchema,
} from "../../domain/angr/angrEvidence.js";
import {
  ANGR_BRIDGE_DIR_ENV,
  ANGR_JOBS_ENV,
  ANGR_LIMITS,
  ANGR_OPERATION_TIMEOUT_SETTING,
  ANGR_PYTHON_ENV,
} from "../../domain/angr/angrLimits.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/**
 * The symbolic lane answers: can these bytes reach that address under these
 * assumptions, what does one bounded exploration keep alive, and what
 * control-flow graph does a second engine derive for this artifact?
 *
 * Every job runs in a fresh angr process through REA's own sidecar. Path
 * conditions are reported as structure, and every model value as a digest.
 */
export const ANGR_TOOL_CONTRACTS = [
  {
    name: "find_paths_to_target",
    ...toolContractMetadata("find_paths_to_target"),
    description: `Ask angr whether the selected artifact can reach one of find_addresses from entry, given caller-supplied assertions over symbolic registers or a symbolic stdin window, and report each satisfying path's condition tree as structure. Constants in a condition are reported only as SHA-256 digests and every model value only as a digest, so no symbolic solution that could carry target secrets is echoed back. A found path is one angr could model with its loader and stub environment inside max_states, max_steps, and timeout_ms; no reachable path is a bounded negative, not a proof of unreachability. Jobs run in a fresh angr process through REA's sidecar (${ANGR_BRIDGE_DIR_ENV}, ${ANGR_PYTHON_ENV}), at most ${String(ANGR_LIMITS.maxJobs)} at once (${ANGR_JOBS_ENV}), with the deadline from ${ANGR_OPERATION_TIMEOUT_SETTING} when the request names none.`,
    kind: "symbolic-engine",
    inputSchema: findPathsToTargetInputSchema,
    outputSchema: evidenceResultOf(findPathsToTargetResultSchema),
    examples: [
      {
        title: "Ask whether a symbolic stdin byte reaches a compare site",
        input: {
          path: "/artifacts/firmware/router.bin",
          entry: "0x401000",
          stdin_bytes: 16,
          assertions: [
            {
              operand: { kind: "stdin", offset: 0, width_bytes: 1 },
              relation: "eq",
              value: "0x41",
            },
          ],
          find_addresses: ["0x4010a0"],
          max_paths: 2,
        },
      },
      {
        title: "Constrain one argument register and look for the accept path",
        input: {
          path: "/artifacts/firmware/router.bin",
          entry: "0x401000",
          symbolic_registers: ["rdi"],
          assertions: [
            {
              operand: { kind: "register", name: "rdi" },
              relation: "ge",
              value: "0x1000",
            },
          ],
          find_addresses: ["0x401140"],
          avoid_addresses: ["0x401180"],
        },
      },
    ],
  },
  {
    name: "run_symbolic_function_exploration",
    ...toolContractMetadata("run_symbolic_function_exploration"),
    description: `Explore one function's states from entry with angr and report what the exploration kept alive: how many states were explored, found, avoided, deadended, and errored, which blocks were visited, and the condition structure of every found state. Values are never returned — model values are SHA-256 digests and path-condition constants are digests too. Counts describe this one bounded exploration, not the function's real path count. max_states, max_steps, and timeout_ms bound the job, and ${String(ANGR_LIMITS.maxVisitedBlocks)} visited block addresses and ${String(ANGR_LIMITS.maxPaths)} found states are retained before coverage is marked partial. Runs in a fresh angr process through REA's sidecar (${ANGR_BRIDGE_DIR_ENV}, ${ANGR_PYTHON_ENV}), at most ${String(ANGR_LIMITS.maxJobs)} at once (${ANGR_JOBS_ENV}).`,
    kind: "symbolic-engine",
    inputSchema: runSymbolicFunctionExplorationInputSchema,
    outputSchema: evidenceResultOf(runSymbolicFunctionExplorationResultSchema),
    examples: [
      {
        title:
          "Explore a parser function with symbolic input and one avoid site",
        input: {
          path: "/artifacts/firmware/router.bin",
          entry: "0x401000",
          stdin_bytes: 64,
          find_addresses: ["0x4010a0"],
          avoid_addresses: ["0x401200"],
          max_states: 32,
        },
      },
    ],
  },
  {
    name: "recover_control_flow_angr",
    ...toolContractMetadata("recover_control_flow_angr"),
    description: `Recover a control-flow graph for the whole artifact with angr and report its functions, basic blocks, successors, and edge count as addresses only. Use it as a second engine to cross-check what rizin or Ghidra recovered: an edge the other engine found and angr did not is a question about the artifact, not a settled answer either way. No function, block, or symbol name is reported, because a name can carry text read from the target; the result is marked as target-derived. At most ${String(ANGR_LIMITS.maxFunctions)} functions and ${String(ANGR_LIMITS.maxBlocks)} blocks are retained, and an unresolved indirect branch contributes its block without a successor. Runs in a fresh angr process through REA's sidecar (${ANGR_BRIDGE_DIR_ENV}, ${ANGR_PYTHON_ENV}).`,
    kind: "symbolic-engine",
    inputSchema: recoverControlFlowAngrInputSchema,
    outputSchema: evidenceResultOf(recoverControlFlowAngrResultSchema),
    examples: [
      {
        title: "Recover the CFG to compare against a rizin analysis",
        input: { path: "/artifacts/firmware/router.bin", max_blocks: 4096 },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
