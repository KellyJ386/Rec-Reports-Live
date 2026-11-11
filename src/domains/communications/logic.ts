// Pure logic for the communications domain: notice audiences, ordering, notification links,
// recipient lists and notification preferences. No database access, so it is unit tested.
import { z } from 'zod';
import type { Paged } from '@/lib/paging';

const guidSchema = z.guid();

// ---- labels ----

export function urgencyLabel(urgency: string): string {
  if (urgency === 'critical') return 'CRITICAL';
  if (urgency === 'high') return 'Important';
  return 'Normal';
}

/** Critical and important are flagged in words, never by colour alone. */
export function urgencyFlag(urgency: string): string {
  if (urgency === 'critical') return 'CRITICAL: ';
  if (urgency === 'high') return 'Important: ';
  return '';
}

export function noticeStatusLabel(status: string): string {
  if (status === 'draft') return 'Draft';
  if (status === 'published') return 'Published';
  if (status === 'archived') return 'Archived';
  return status;
}

export function excerpt(text: string, max = 80): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1).trimEnd()}…`;
}

// ---- notification links ----

const MAX_LINK_LENGTH = 500;
// The same shape the database accepts for notifications.link_path.
const LINK_PATH = /^\/[A-Za-z0-9/_.~%?=&-]*$/;

/**
 * A stored link path, if it is safe to render as a link: an app-relative path that starts with
 * one slash. Never "//host", never a scheme, never a backslash, never ".." segments, never
 * longer than 500 characters. Anything else returns null and is shown as plain text.
 */
export function safeLinkPath(path: string | null | undefined): string | null {
  if (typeof path !== 'string') return null;
  if (path.length === 0 || path.length > MAX_LINK_LENGTH) return null;
  if (!LINK_PATH.test(path)) return null;
  if (path.startsWith('//') || path.includes('//')) return null;
  const pathOnly = path.split(/[?#]/)[0] ?? '';
  if (pathOnly.split('/').some((segment) => segment === '..' || segment === '.')) return null;
  try {
    const base = 'http://same-origin.invalid';
    if (new URL(path, base).origin !== base) return null;
  } catch {
    return null;
  }
  return path;
}

// ---- notice audiences ----

export type AudienceRow = { location_id: string | null; job_title_id: string | null };

export type AudienceInput = {
  /** 'organization' = the whole organization; 'locations' = the chosen locations. */
  scope: string;
  locationIds: readonly string[];
  /** Empty = everyone in those places. */
  jobTitleIds: readonly string[];
  /** The person holds communications = admin at organization scope. */
  canOrgWide: boolean;
  /** Locations where the person holds communications = admin. */
  allowedLocationIds: readonly string[];
};

export type AudienceOptions = {
  /** Offer "the whole organization". */
  allowOrganization: boolean;
  /** Several locations may be ticked (organization-scope admins); otherwise exactly one. */
  allowMultipleLocations: boolean;
  locations: { id: string; name: string }[];
};

/** What the compose form offers: only the scopes this person may address. */
export function buildAudienceOptions(
  canOrgWide: boolean,
  allowedLocations: readonly { id: string; name: string }[],
): AudienceOptions {
  return {
    allowOrganization: canOrgWide,
    allowMultipleLocations: canOrgWide,
    locations: [...allowedLocations].sort((a, b) => a.name.localeCompare(b.name)),
  };
}

const MAX_AUDIENCE_ROWS = 200;

/**
 * The notice's home scope and audience rows from the form. A notice homed at the organization
 * (home null) can address any location; a notice homed at one location can address only that
 * location (the notice_audiences policy). Rows are every place x every chosen job title, or
 * x "everyone" when no title is chosen. The database re-checks all of it.
 */
export function buildAudience(
  input: AudienceInput,
): { ok: true; home: string | null; audiences: AudienceRow[] } | { ok: false; message: string } {
  const titles = [...new Set(input.jobTitleIds)];
  if (!titles.every((t) => guidSchema.safeParse(t).success)) {
    return { ok: false, message: 'Pick job titles from the list.' };
  }
  const titleChoices: (string | null)[] = titles.length === 0 ? [null] : titles;

  let home: string | null;
  let places: (string | null)[];
  if (input.scope === 'organization') {
    if (!input.canOrgWide) {
      return { ok: false, message: 'You cannot send a notice to the whole organization.' };
    }
    home = null;
    places = [null];
  } else if (input.scope === 'locations') {
    const ids = [...new Set(input.locationIds)];
    if (ids.length === 0) return { ok: false, message: 'Choose where the notice goes.' };
    const allowed = new Set(input.allowedLocationIds);
    if (!ids.every((id) => guidSchema.safeParse(id).success && allowed.has(id))) {
      return { ok: false, message: 'You cannot send a notice to one of those locations.' };
    }
    if (input.canOrgWide) {
      home = null;
    } else {
      if (ids.length !== 1) {
        return {
          ok: false,
          message: 'Choose one location. You can send to one location at a time.',
        };
      }
      home = ids[0] ?? null;
    }
    places = ids;
  } else {
    return { ok: false, message: 'Choose who the notice is for.' };
  }

  const audiences = places.flatMap((location_id) =>
    titleChoices.map((job_title_id) => ({ location_id, job_title_id })),
  );
  if (audiences.length > MAX_AUDIENCE_ROWS) {
    return { ok: false, message: 'That is too many combinations. Choose fewer places or titles.' };
  }
  return { ok: true, home, audiences };
}

/** Plain sentences for the audience rows of a notice. */
export function describeAudience(
  rows: readonly AudienceRow[],
  locationNames: ReadonlyMap<string, string>,
  titleNames: ReadonlyMap<string, string>,
): string[] {
  return rows.map((r) => {
    const place =
      r.location_id === null
        ? 'the whole organization'
        : (locationNames.get(r.location_id) ?? 'a location');
    if (r.job_title_id === null) return `Everyone at ${place}`;
    return `${titleNames.get(r.job_title_id) ?? 'A job title'} at ${place}`;
  });
}

// ---- reading notices ----

export type NoticeForOrder = {
  id: string;
  urgency: string;
  requires_acknowledgment: boolean;
  publish_at: string | null;
};

const URGENCY_RANK: Record<string, number> = { critical: 0, high: 1, normal: 2 };

/** Required and not yet acknowledged. */
export function needsAcknowledgment(
  notice: Pick<NoticeForOrder, 'id' | 'requires_acknowledgment'>,
  acknowledgedIds: ReadonlySet<string>,
): boolean {
  return notice.requires_acknowledgment && !acknowledgedIds.has(notice.id);
}

/**
 * The reader's order: notices that still need an acknowledgment first, then everything else;
 * inside each part critical before important before normal, then newest first.
 */
export function orderNoticesForReader<T extends NoticeForOrder>(
  notices: readonly T[],
  acknowledgedIds: ReadonlySet<string>,
): T[] {
  const key = (n: T) => [
    needsAcknowledgment(n, acknowledgedIds) ? 0 : 1,
    URGENCY_RANK[n.urgency] ?? 3,
    -(Date.parse(n.publish_at ?? '') || 0),
  ];
  return [...notices].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    for (let i = 0; i < ka.length; i++) {
      const diff = (ka[i] ?? 0) - (kb[i] ?? 0);
      if (diff !== 0) return diff;
    }
    return a.id.localeCompare(b.id);
  });
}

/** One page cut from a list that was sorted in memory. */
export function pageOf<T>(items: readonly T[], page: number, pageSize: number): Paged<T> {
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  const current = Math.min(Math.max(1, page), pages);
  return {
    rows: items.slice((current - 1) * pageSize, current * pageSize),
    total: items.length,
    page: current,
    pageSize,
  };
}

// ---- message recipients ----

export const MAX_RECIPIENTS = 50;

/** Recipient ids from a "to" search param: comma separated, valid ids only, no repeats, at most 50. */
export function parseRecipientIds(raw: string | string[] | undefined): string[] {
  const text = Array.isArray(raw) ? raw.join(',') : (raw ?? '');
  const ids: string[] = [];
  for (const part of text.split(',')) {
    const id = part.trim().toLowerCase();
    if (guidSchema.safeParse(id).success && !ids.includes(id)) ids.push(id);
    if (ids.length >= MAX_RECIPIENTS) break;
  }
  return ids;
}

export function addRecipient(ids: readonly string[], id: string): string[] {
  if (!guidSchema.safeParse(id).success || ids.includes(id) || ids.length >= MAX_RECIPIENTS) {
    return [...ids];
  }
  return [...ids, id];
}

export function removeRecipient(ids: readonly string[], id: string): string[] {
  return ids.filter((x) => x !== id);
}

// ---- notification settings ----

export type ChannelSettings = { email: boolean; push: boolean };

/** A channel with no saved row is on (the database default). */
export function channelSettings(
  rows: readonly { channel: string; enabled: boolean }[],
): ChannelSettings {
  const find = (channel: string) => rows.find((r) => r.channel === channel)?.enabled ?? true;
  return { email: find('email'), push: find('push') };
}
