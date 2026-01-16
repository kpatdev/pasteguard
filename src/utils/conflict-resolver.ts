/**
 * Conflict resolution for overlapping entities
 *
 * Based on Microsoft Presidio's conflict resolution logic:
 * https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/anonymizer_engine.py
 */

export interface EntityWithScore {
  start: number;
  end: number;
  score: number;
  entity_type: string;
}

interface Interval {
  start: number;
  end: number;
}

function overlaps(a: Interval, b: Interval): boolean {
  return a.start < b.end && b.start < a.end;
}

function isContainedIn(a: Interval, b: Interval): boolean {
  return b.start <= a.start && b.end >= a.end;
}

function groupBy<T>(items: T[], keyFn: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    const group = groups.get(key) ?? [];
    group.push(item);
    groups.set(key, group);
  }
  return groups;
}

/**
 * Merge overlapping intervals. Returns new array (does not mutate input).
 */
function mergeOverlapping<T extends Interval>(
  intervals: T[],
  merge: (a: T, b: T) => T,
): T[] {
  if (intervals.length <= 1) return [...intervals];

  const sorted = [...intervals].sort((a, b) => a.start - b.start);
  const result: T[] = [sorted[0]];

  for (let i = 1; i < sorted.length; i++) {
    const current = sorted[i];
    const last = result[result.length - 1];

    if (overlaps(current, last)) {
      // Replace last with merged interval
      result[result.length - 1] = merge(last, current);
    } else {
      result.push(current);
    }
  }

  return result;
}

/**
 * Remove entities that are contained in another or have same indices with lower score.
 */
function removeConflicting<T extends EntityWithScore>(entities: T[]): T[] {
  if (entities.length <= 1) return [...entities];

  // Sort by start, then by score descending (higher score first)
  const sorted = [...entities].sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    if (a.end !== b.end) return a.end - b.end;
    return b.score - a.score;
  });

  const result: T[] = [];

  for (const entity of sorted) {
    const hasConflict = result.some((kept) => {
      if (entity.start === kept.start && entity.end === kept.end) {
        return true;
      }
      return isContainedIn(entity, kept);
    });

    if (!hasConflict) {
      result.push(entity);
    }
  }

  return result;
}

/**
 * Resolve conflicts between overlapping entities using Presidio's algorithm.
 *
 * Phase 1: Merge overlapping entities of the same type (expand boundaries, keep highest score)
 * Phase 2: Remove conflicting entities of different types (contained or same indices with lower score)
 */
export function resolveConflicts<T extends EntityWithScore>(entities: T[]): T[] {
  if (entities.length <= 1) return [...entities];

  const byType = groupBy(entities, (e) => e.entity_type);
  const afterMerge: T[] = [];

  for (const group of byType.values()) {
    const merged = mergeOverlapping(group, (a, b) => ({
      ...a,
      start: Math.min(a.start, b.start),
      end: Math.max(a.end, b.end),
      score: Math.max(a.score, b.score),
    }));
    afterMerge.push(...merged);
  }

  return removeConflicting(afterMerge);
}

/**
 * Simple overlap resolution for entities without scores.
 * Uses length as tiebreaker (longer wins). For secrets detection.
 */
export function resolveConflictsSimple<T extends Interval>(entities: T[]): T[] {
  if (entities.length <= 1) return [...entities];

  const sorted = [...entities].sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return b.end - b.start - (a.end - a.start);
  });

  const result: T[] = [sorted[0]];

  for (let i = 1; i < sorted.length; i++) {
    const current = sorted[i];
    const last = result[result.length - 1];

    if (current.start >= last.end) {
      result.push(current);
    }
  }

  return result;
}
