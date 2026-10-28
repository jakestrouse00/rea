import { fileURLToPath } from "node:url";

import { DISCOVERY_BLEAK_REMEDIATION } from "../DiscoveryRelease.js";

/** The bundled bleak bridge this checkout ships. */
export const BLEAK_BRIDGE_PATH = fileURLToPath(
  new URL("../../../bridge/ble/bleak_bridge.py", import.meta.url),
);

/** The helper command a GATT session spawns, and which transport it drives. */
export interface GattHelperSelection {
  readonly transport: "corebluetooth" | "bleak";
  readonly executable: string;
  /** Arguments placed before the helper's own flags (the bridge script path). */
  readonly leadingArguments: readonly string[];
}

/**
 * Select the GATT helper for one session. A caller-built CoreBluetooth helper
 * wins when it is configured; otherwise an absolute Python interpreter selects
 * the bundled bleak bridge. Neither selected is a refusal, never a fallback to
 * a guessed interpreter.
 */
export const selectGattHelper = (tools: {
  readonly bleGatt: string | null;
  readonly bleakPython: string | null;
}): GattHelperSelection | null => {
  if (tools.bleGatt !== null)
    return {
      transport: "corebluetooth",
      executable: tools.bleGatt,
      leadingArguments: [],
    };
  if (tools.bleakPython !== null)
    return {
      transport: "bleak",
      executable: tools.bleakPython,
      leadingArguments: [BLEAK_BRIDGE_PATH],
    };
  return null;
};

/** Remediation shared by every GATT refusal, naming both selections. */
export const gattHelperRemediation = (): string =>
  `Set REA_BLE_GATT_PATH to an absolute caller-compiled CoreBluetooth GATT helper, or REA_BLEAK_PYTHON to an absolute Python 3 interpreter that runs the bundled bleak bridge. ${DISCOVERY_BLEAK_REMEDIATION}`;
