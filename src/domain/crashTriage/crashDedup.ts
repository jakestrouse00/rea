import type { SanitizerClass } from "./crashReport.js";

/** One stored crash, reduced to the fields deduplication needs. */
export interface CrashRecordSummary {
  readonly crashId: string;
  readonly dedupId: string;
  readonly dedupHash: string;
  readonly crashKind: string;
  readonly sanitizerClass: SanitizerClass;
  /** Normalized frames the record was hashed from, in report order. */
  readonly frames: readonly string[];
  /** Every frame the report carried, including those beyond the state window. */
  readonly frameCount: number;
  readonly occurrenceCount: number;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
}

/** One deduplicated crash group. */
export interface CrashDedupGroup {
  readonly dedupId: string;
  readonly dedupHash: string;
  readonly crashKind: string;
  readonly sanitizerClass: SanitizerClass;
  /** Normalized frames the state hash covers. */
  readonly topFrames: readonly string[];
  /** Every frame the representative report carried. */
  readonly frameCount: number;
  /** Occurrences across every crash record in the group. */
  readonly occurrenceCount: number;
  /** Every crash record id in the group, in first-seen order. */
  readonly crashIds: readonly string[];
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
}

export interface CrashDedupGrouping {
  readonly groups: readonly CrashDedupGroup[];
  /** Whether the caller's group bound stopped the listing. */
  readonly truncated: boolean;
}

const compareText = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

/**
 * Group stored crashes by their crash-state identity.
 *
 * The identity is assigned once, when a report is parsed, so this function
 * never re-derives it: two records belong together exactly when the store
 * recorded the same dedup id. Occurrence counts are summed, not inferred from
 * neighbouring records.
 */
export const groupCrashesByDedup = (
  records: readonly CrashRecordSummary[],
  maxGroups: number,
): CrashDedupGrouping => {
  const groups = new Map<
    string,
    {
      readonly dedupHash: string;
      readonly crashKind: string;
      readonly sanitizerClass: SanitizerClass;
      readonly frames: readonly string[];
      frameCount: number;
      occurrenceCount: number;
      readonly crashIds: string[];
      firstSeenAt: string;
      lastSeenAt: string;
    }
  >();
  for (const record of records) {
    const existing = groups.get(record.dedupId);
    if (existing === undefined) {
      groups.set(record.dedupId, {
        dedupHash: record.dedupHash,
        crashKind: record.crashKind,
        sanitizerClass: record.sanitizerClass,
        frames: record.frames,
        frameCount: record.frameCount,
        occurrenceCount: record.occurrenceCount,
        crashIds: [record.crashId],
        firstSeenAt: record.firstSeenAt,
        lastSeenAt: record.lastSeenAt,
      });
      continue;
    }
    existing.frameCount = Math.max(existing.frameCount, record.frameCount);
    existing.occurrenceCount += record.occurrenceCount;
    existing.crashIds.push(record.crashId);
    if (record.firstSeenAt < existing.firstSeenAt)
      existing.firstSeenAt = record.firstSeenAt;
    if (record.lastSeenAt > existing.lastSeenAt)
      existing.lastSeenAt = record.lastSeenAt;
  }
  const ordered = [...groups.entries()]
    .map(([dedupId, group]): CrashDedupGroup => ({
      dedupId,
      dedupHash: group.dedupHash,
      crashKind: group.crashKind,
      sanitizerClass: group.sanitizerClass,
      topFrames: group.frames,
      frameCount: group.frameCount,
      occurrenceCount: group.occurrenceCount,
      crashIds: group.crashIds,
      firstSeenAt: group.firstSeenAt,
      lastSeenAt: group.lastSeenAt,
    }))
    .sort(
      (left, right) =>
        compareText(left.firstSeenAt, right.firstSeenAt) ||
        compareText(left.dedupId, right.dedupId),
    );
  const bounded = Math.max(Math.trunc(maxGroups), 0);
  return {
    groups: ordered.slice(0, bounded),
    truncated: ordered.length > bounded,
  };
};
