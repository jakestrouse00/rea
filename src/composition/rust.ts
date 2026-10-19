import { RustBinaryService } from "../application/rust/RustBinaryService.js";
import { RustSymbolsService } from "../application/rust/RustSymbolsService.js";
import { RustBinaryProvider } from "../rust/RustBinaryProvider.js";

/** Compose bundled offline inspection without a Rust toolchain or any child process. */
export const createRustBinaryService = (): RustBinaryService =>
  new RustBinaryService(new RustBinaryProvider());

/** Compose offline symbol reading from the same bounded artifact reader. */
export const createRustSymbolsService = (): RustSymbolsService =>
  new RustSymbolsService(new RustBinaryProvider());
