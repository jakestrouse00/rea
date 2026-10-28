import { readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";

import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import { LAB_VM_MAX_WORKSPACE_ENTRIES } from "../domain/vmlab/labVm.js";

/** One admitted workspace file observation. */
export interface WorkspaceEntry {
  readonly size: number;
  readonly modifiedMs: number;
}

/** A bounded workspace inventory in workspace-relative path order. */
export interface WorkspaceInventory {
  readonly entries: ReadonlyMap<string, WorkspaceEntry>;
  readonly truncated: boolean;
}

/**
 * Inventory the regular files of a caller-selected workspace.
 *
 * Directories are descended into, and symbolic links, sockets, FIFOs and
 * device nodes are neither traversed nor reported. A link therefore cannot
 * pull an unrelated host directory into the observed scope, and a command that
 * only creates or removes a link is not reported as a produced or removed path.
 */
export const inventoryWorkspace = async (
  root: string,
  operation: string,
  signal: AbortSignal | undefined,
): Promise<Result<WorkspaceInventory, AnalysisError>> => {
  const entries = new Map<string, WorkspaceEntry>();
  let truncated = false;
  const walk = async (directory: string, prefix: string): Promise<void> => {
    if (entries.size >= LAB_VM_MAX_WORKSPACE_ENTRIES) {
      truncated = true;
      return;
    }
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    );
    for (const child of children) {
      if (signal?.aborted === true)
        throw new AnalysisCancelledError(operation, {
          cause: signal.reason,
        });
      if (entries.size >= LAB_VM_MAX_WORKSPACE_ENTRIES) {
        truncated = true;
        return;
      }
      const relative = prefix === "" ? child.name : `${prefix}/${child.name}`;
      const absolute = join(directory, child.name);
      if (child.isDirectory()) {
        await walk(absolute, relative);
        continue;
      }
      if (!child.isFile()) continue;
      const observed = await stat(absolute, { bigint: true });
      entries.set(relative, {
        size: Number(observed.size),
        modifiedMs: Number(observed.mtimeMs),
      });
    }
  };
  try {
    await walk(root, "");
    return ok({ entries, truncated });
  } catch (cause: unknown) {
    if (cause instanceof AnalysisError) return err(cause);
    return err(
      new AnalysisInputError(operation, {
        cause,
        userMessage: `The lab VM workspace could not be inventoried: ${root}`,
      }),
    );
  }
};

/** What one command did to the workspace, in workspace-relative order. */
export interface WorkspaceChange {
  readonly produced: readonly string[];
  readonly modified: readonly string[];
  readonly removed: readonly string[];
  readonly truncated: boolean;
}

/** Compare two inventories from the same session into sorted path lists. */
export const workspaceChange = (
  before: WorkspaceInventory,
  after: WorkspaceInventory,
  limit: number,
): WorkspaceChange => {
  const produced: string[] = [];
  const modified: string[] = [];
  const removed: string[] = [];
  let truncated = before.truncated || after.truncated;
  const retain = (target: string[], path: string): void => {
    if (target.length >= limit) {
      truncated = true;
      return;
    }
    target.push(path);
  };
  for (const [path, entry] of after.entries) {
    const previous = before.entries.get(path);
    if (previous === undefined) retain(produced, path);
    else if (
      previous.size !== entry.size ||
      previous.modifiedMs !== entry.modifiedMs
    )
      retain(modified, path);
  }
  for (const path of before.entries.keys())
    if (!after.entries.has(path)) retain(removed, path);
  return {
    produced: produced.sort(),
    modified: modified.sort(),
    removed: removed.sort(),
    truncated,
  };
};

/** Resolve one caller-supplied workspace directory for admission. */
export const resolveWorkspacePath = async (
  workspacePath: string,
  operation: string,
): Promise<Result<string, AnalysisError>> => {
  try {
    const observed = await stat(workspacePath);
    if (!observed.isDirectory())
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage: `The lab VM workspace is not a directory: ${workspacePath}`,
          },
          [
            {
              path: ["workspace_path"],
              reason: "invalid_value",
              message: "Expected an existing absolute directory on this host.",
            },
          ],
        ),
      );
    return ok(resolve(workspacePath));
  } catch (cause: unknown) {
    return err(
      new AnalysisInputError(
        operation,
        {
          cause,
          userMessage: `The lab VM workspace could not be read: ${workspacePath}`,
        },
        [
          {
            path: ["workspace_path"],
            reason: "invalid_value",
            message: "Expected an existing absolute directory on this host.",
          },
        ],
      ),
    );
  }
};
