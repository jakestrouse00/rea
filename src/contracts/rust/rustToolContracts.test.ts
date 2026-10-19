import { expect, it } from "vitest";
import { RUST_TOOL_CONTRACTS } from "./rustToolContracts.js";

it("registers the bounded paged symbol inspection contract", () => {
  const symbols = RUST_TOOL_CONTRACTS.find(
    (contract) => contract.name === "inspect_rust_symbols",
  );
  expect(symbols).toBeDefined();
  expect(symbols?.kind).toBe("artifact-provider");
  expect(symbols?.description ?? "").toMatch(/500 entries/u);
  expect(symbols?.description ?? "").toMatch(/200000 symbols/u);
});

it("keeps the dependency contract alongside the symbol contract", () => {
  const names = RUST_TOOL_CONTRACTS.map((contract) => contract.name);
  expect(names).toEqual(["inspect_rust_binary", "inspect_rust_symbols"]);
});
