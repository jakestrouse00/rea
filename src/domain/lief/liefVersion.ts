import {
  LIEF_MAX_SUPPORTED_VERSION_EXCLUSIVE,
  LIEF_MIN_SUPPORTED_VERSION,
} from "./liefLimits.js";

/** A three-part numeric release tuple; prerelease suffixes are discarded. */
export type LiefVersionTuple = readonly [number, number, number];

/** Parse `major.minor.patch` (a `-rc1`/`+local` suffix is ignored). */
export const parseLiefVersion = (value: string): LiefVersionTuple | null => {
  const match = /^(\d+)\.(\d+)(?:\.(\d+))?/u.exec(value.trim());
  if (match === null) return null;
  const [, major, minor, patch] = match;
  return [Number(major), Number(minor), Number(patch ?? "0")];
};

const compare = (left: LiefVersionTuple, right: LiefVersionTuple): number => {
  for (let index = 0; index < 3; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
};

/**
 * Whether a reported LIEF release sits in the range this bridge targets.
 * The range is declared, not verified per patch release.
 */
export const liefVersionSupported = (value: string): boolean => {
  const parsed = parseLiefVersion(value);
  if (parsed === null) return false;
  const minimum = parseLiefVersion(LIEF_MIN_SUPPORTED_VERSION);
  const maximum = parseLiefVersion(LIEF_MAX_SUPPORTED_VERSION_EXCLUSIVE);
  if (minimum === null || maximum === null) return false;
  return compare(parsed, minimum) >= 0 && compare(parsed, maximum) < 0;
};

/** The documented supported range, for refusal messages and docs. */
export const LIEF_SUPPORTED_RANGE = `LIEF >= ${LIEF_MIN_SUPPORTED_VERSION} and < ${LIEF_MAX_SUPPORTED_VERSION_EXCLUSIVE}`;
