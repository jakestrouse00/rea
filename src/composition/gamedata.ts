import { GameDataProvider } from "../gamedata/GameDataProvider.js";
import { GameDataService } from "../gamedata/GameDataService.js";

/** Compose structure-only game-container inspection without starting any process. */
export const createGameDataService = (): GameDataService =>
  new GameDataService(new GameDataProvider());
