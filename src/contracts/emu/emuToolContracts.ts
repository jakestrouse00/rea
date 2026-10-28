import {
  assembleBytesInputSchema,
  assembleBytesResultSchema,
  emulateFunctionInputSchema,
  emulateFunctionResultSchema,
} from "../../domain/emu/emuEmulation.js";
import {
  EMU_BRIDGE_DIR_ENV,
  EMU_LIMITS,
  EMU_PYTHON_ENV,
} from "../../domain/emu/emuLimits.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/**
 * The emulation lane answers: what does this code do to registers and memory
 * when it runs, and what bytes would a patch assemble to?
 *
 * One bounded job runs in an isolated Unicorn CPU and memory model through
 * REA's own sidecar; nothing executes natively and no operating system,
 * loader, import, or syscall is modelled. Evidence carries typed register
 * values, memory digests, executed address pairs, and call counts only.
 */
export const EMU_TOOL_CONTRACTS = [
  {
    name: "emulate_function_isolated",
    ...toolContractMetadata("emulate_function_isolated"),
    description: `Run one bounded, isolated emulation of a caller-selected code slice with stubbed arguments and report what it did: typed register values, memory-window digests, executed address pairs, call count, executed steps, and the exit reason. The code comes from an absolute file path plus offset and length, or from caller-supplied hex bytes, and is emulated only inside Unicorn's CPU and memory model through REA's sidecar (${EMU_BRIDGE_DIR_ENV} and ${EMU_PYTHON_ENV}, pinned to Unicorn 2.1.x). No instruction executes natively on the host, nothing is written to the target, and no operating system, loader, import, or syscall is modelled, so a call into an unmapped address ends the job instead of being satisfied. Observed memory windows are reported as length and SHA-256 only, never as bytes; code bytes and stub argument values are never echoed. max_steps and timeout_ms bound every job, and ${String(EMU_LIMITS.maxEdges)} distinct executed edges with ${String(EMU_LIMITS.maxCallTargets)} distinct call targets are retained before coverage is marked partial.`,
    kind: "emulator",
    inputSchema: emulateFunctionInputSchema,
    outputSchema: evidenceResultOf(emulateFunctionResultSchema),
    examples: [
      {
        title: "Emulate one function body from a file and read two registers",
        input: {
          arch: "x86_64",
          source: {
            kind: "file",
            path: "/artifacts/firmware/app.bin",
            offset: 4096,
            length: 128,
          },
          code_base: "0x401000",
          args: ["0x1", "0x2"],
          max_steps: 10000,
          observe_registers: ["rax", "rdx"],
          observe_memory: [{ address: "0x7ffd0000", length: 32 }],
        },
      },
      {
        title: "Check a caller-supplied instruction snippet",
        input: {
          arch: "arm64",
          source: { kind: "hex", hex: "c0035fd6" },
          entry_offset: 0,
        },
      },
    ],
  },
  {
    name: "assemble_bytes",
    ...toolContractMetadata("assemble_bytes"),
    description: `Encode assembly source for one architecture through Keystone in REA's sidecar and return the exact bytes, their size and SHA-256, the base address they were assembled at, and the encoded statement count. Use it to craft or verify a patch slice before writing it elsewhere; REA never writes the bytes to a target and never disassembles here, because rizin and objdump already answer disassembly. At most ${String(EMU_LIMITS.maxAssembledBytes)} bytes are encoded per request, and an unsupported architecture, endianness, or instruction is a typed refusal rather than a guessed encoding. ${EMU_BRIDGE_DIR_ENV} and ${EMU_PYTHON_ENV} select the sidecar, which is pinned to Unicorn 2.1.x with Keystone.`,
    kind: "emulator",
    inputSchema: assembleBytesInputSchema,
    outputSchema: evidenceResultOf(assembleBytesResultSchema),
    examples: [
      {
        title: "Assemble a return for an x86-64 patch stub",
        input: { arch: "x86_64", assembly: "ret" },
      },
      {
        title: "Assemble a branch at a known address",
        input: {
          arch: "arm64",
          base_address: "0x401000",
          assembly: "b #0x401020",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
