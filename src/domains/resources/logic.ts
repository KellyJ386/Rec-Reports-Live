// Pure logic for the resources domain: grouping spaces under parents, grouping weekly
// hours by ISO weekday, building an hours row from form values, checking a parent choice.
// No database access, so it is unit tested directly.
import { ISO_WEEKDAYS } from '@/lib/time';

export type SpaceLike = {
  id: string;
  name: string;
  parent_space_id: string | null;
  sort_order: number;
};

export type SpaceGroup<S extends SpaceLike> = { space: S; children: S[] };

const bySortThenName = (a: SpaceLike, b: SpaceLike) =>
  a.sort_order - b.sort_order || a.name.localeCompare(b.name) || a.id.localeCompare(b.id);

/**
 * Top-level spaces, each with its sub-spaces. A sub-space whose parent is not in the list
 * (for example, the parent was filtered out) is shown as a top-level entry rather than dropped.
 */
export function groupSpaces<S extends SpaceLike>(spaces: readonly S[]): SpaceGroup<S>[] {
  const ids = new Set(spaces.map((s) => s.id));
  const tops = spaces.filter((s) => s.parent_space_id === null || !ids.has(s.parent_space_id));
  return [...tops].sort(bySortThenName).map((space) => ({
    space,
    children: spaces.filter((c) => c.parent_space_id === space.id).sort(bySortThenName),
  }));
}

/** Spaces that may be chosen as a parent: top level, not archived, not the space itself. */
export function parentChoices<S extends SpaceLike & { archived_at: string | null }>(
  spaces: readonly S[],
  excludeId?: string,
): S[] {
  return spaces
    .filter((s) => s.parent_space_id === null && s.archived_at === null && s.id !== excludeId)
    .sort(bySortThenName);
}

export type ParentCheck = { ok: true } | { ok: false; message: string };

/** The parent must exist at the same location, be top level and not archived. */
export function checkParent(
  parent: { parent_space_id: string | null; archived_at: string | null } | null,
  selfId?: string,
  parentId?: string,
): ParentCheck {
  if (selfId && parentId === selfId)
    return { ok: false, message: 'A space cannot be its own parent.' };
  if (!parent) return { ok: false, message: 'Pick a parent space at this location.' };
  if (parent.parent_space_id !== null) {
    return {
      ok: false,
      message: 'Pick a top-level space as the parent. A sub-space cannot have sub-spaces.',
    };
  }
  if (parent.archived_at !== null) return { ok: false, message: 'That parent space is archived.' };
  return { ok: true };
}

export type HoursRow = {
  id: string;
  day_of_week: number;
  opens_at: string;
  closes_at: string;
  effective_from: string | null;
  effective_to: string | null;
};

export type DayHours<R extends HoursRow> = { day: number; label: string; rows: R[] };

/** Seven entries, Monday (1) to Sunday (7), each with its rows ordered by opening time. */
export function groupHoursByDay<R extends HoursRow>(rows: readonly R[]): DayHours<R>[] {
  return ISO_WEEKDAYS.map(({ value, label }) => ({
    day: value,
    label,
    rows: rows
      .filter((r) => r.day_of_week === value)
      .sort((a, b) => a.opens_at.localeCompare(b.opens_at) || a.id.localeCompare(b.id)),
  }));
}

/**
 * Form values to the strings the hours schema expects. "Closes at midnight" gives 24:00.
 * Returns null when a time is missing.
 */
export function hoursTimes(input: {
  opens: string | null;
  closes: string | null;
  closesAtMidnight: boolean;
}): { opens_at: string; closes_at: string } | null {
  if (!input.opens) return null;
  if (input.closesAtMidnight) return { opens_at: input.opens, closes_at: '24:00' };
  if (!input.closes) return null;
  return { opens_at: input.opens, closes_at: input.closes };
}

/** Rows that share a weekday and overlap in time (the database has no overlap constraint yet). */
export function overlapsExisting(
  existing: readonly Pick<HoursRow, 'day_of_week' | 'opens_at' | 'closes_at'>[],
  candidate: { day_of_week: number; opens_at: string; closes_at: string },
): boolean {
  const secs = (t: string) => {
    const [h = '0', m = '0', s = '0'] = t.split(':');
    return Number(h) * 3600 + Number(m) * 60 + Number(s);
  };
  const a0 = secs(candidate.opens_at);
  const a1 = secs(candidate.closes_at);
  return existing.some(
    (e) =>
      e.day_of_week === candidate.day_of_week && a0 < secs(e.closes_at) && secs(e.opens_at) < a1,
  );
}
