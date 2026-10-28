/**
 * REA appends this marker-bearing epilogue to every caller script it loads.
 * The target runtime reports the script's `rpc.exports` names and arities once
 * the caller's top-level code has run; the host treats that report as an
 * observation of the target rather than caller-authoritative metadata.
 */
export const FRIDA_RPC_INVENTORY_KEY = "__rea_frida_rpc_inventory__";

/** Bound the reported export list before retaining it. No runtime override. */
export const MAX_RPC_EXPORTS = 256;

/** Bound one reported export name before retaining it. No runtime override. */
export const MAX_RPC_EXPORT_NAME_BYTES = 256;

export const FRIDA_RPC_INVENTORY_EPILOGUE = `
;(function () {
  try {
    var exported = typeof rpc !== "undefined" && rpc !== null ? rpc.exports : undefined;
    var entries = [];
    if (typeof exported === "object" && exported !== null) {
      var names = Object.keys(exported);
      for (var index = 0; index < names.length; index++) {
        var entry = exported[names[index]];
        entries.push({
          name: names[index],
          parameters: typeof entry === "function" ? entry.length : null,
        });
      }
    }
    send({ ${FRIDA_RPC_INVENTORY_KEY}: entries });
  } catch (error) {
    send({ ${FRIDA_RPC_INVENTORY_KEY}: null });
  }
})();
`;

/** One REA-owned inventory report read out of a captured script message. */
export type RpcInventoryReport =
  | { readonly reported: false }
  | { readonly reported: true; readonly entries: unknown };

/** Read the epilogue's report, distinguishing "no report" from "unavailable". */
export const reportedRpcInventory = (payload: unknown): RpcInventoryReport =>
  typeof payload === "object" &&
  payload !== null &&
  !Array.isArray(payload) &&
  Object.hasOwn(payload, FRIDA_RPC_INVENTORY_KEY)
    ? { reported: true, entries: Reflect.get(payload, FRIDA_RPC_INVENTORY_KEY) }
    : { reported: false };
