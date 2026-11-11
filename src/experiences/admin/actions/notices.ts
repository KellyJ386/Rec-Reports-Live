'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireModulePermission } from '@/lib/auth';
import { blankToNull } from '@/lib/text';
import { zonedLocalToUtc } from '@/lib/time';
import { getLocationsWithPermission } from '../access';
import {
  BAD_ID,
  NOT_CONFIRMED,
  activeOrgId,
  bad,
  confirmed,
  fromResult,
  guid,
  str,
  zodProblem,
  type AdminFormState,
} from './helpers';
import {
  archiveNotice,
  buildAudience,
  createNoticeDraft,
  getNotice,
  noticeCreateSchema,
  noticeUpdateSchema,
  publishNotice,
  updateNoticeDraft,
} from '@/domains/communications';
import { getLocation, getOrganizationSettings } from '@/domains/organizations';

function refresh(id?: string) {
  revalidatePath('/app/admin/notices');
  if (id) revalidatePath(`/app/admin/notices/${id}`);
  revalidatePath('/app/notices');
  revalidatePath('/app');
}

/** The time zone the form's times are read in: the home location's, else the organization's. */
async function noticeZone(orgId: string, homeLocationId: string | null): Promise<string> {
  if (homeLocationId) {
    const location = await getLocation(orgId, homeLocationId);
    if (location.ok && location.data) return location.data.timezone;
  }
  const settings = await getOrganizationSettings(orgId);
  return settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
}

/** '' = not set (null); a bad value is undefined. */
function readTime(formData: FormData, name: string, zone: string): string | null | undefined {
  const text = blankToNull(formData.get(name));
  if (text === null) return null;
  return zonedLocalToUtc(text, zone) ?? undefined;
}

export async function createNoticeAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const places = await getLocationsWithPermission(orgId, 'communications', 'admin');
  if (!places.ok) return bad(formData, places.message);

  const audience = buildAudience({
    scope: str(formData, 'scope'),
    locationIds: formData.getAll('location_ids').filter((v): v is string => typeof v === 'string'),
    jobTitleIds: formData.getAll('job_title_ids').filter((v): v is string => typeof v === 'string'),
    canOrgWide: places.orgWide,
    allowedLocationIds: places.data.map((l) => l.id),
  });
  if (!audience.ok) return bad(formData, audience.message);
  await requireModulePermission(orgId, audience.home, 'communications', 'admin');

  const zone = await noticeZone(orgId, audience.home);
  const mode = str(formData, 'publish_mode') || 'draft';
  if (mode !== 'draft' && mode !== 'now' && mode !== 'later') {
    return bad(formData, 'Choose when to publish.');
  }
  const publishAt = mode === 'later' ? readTime(formData, 'publish_at', zone) : null;
  if (mode === 'later' && !publishAt) return bad(formData, 'Enter the date and time to publish.');
  const expiresAt = readTime(formData, 'expires_at', zone);
  if (expiresAt === undefined) return bad(formData, 'Enter a valid expiry date and time.');

  const parsed = noticeCreateSchema.safeParse({
    organization_id: orgId,
    location_id: audience.home,
    title: str(formData, 'title'),
    body: str(formData, 'body'),
    urgency: str(formData, 'urgency') || 'normal',
    requires_acknowledgment: formData.get('requires_acknowledgment') === 'yes',
    publish_at: publishAt,
    expires_at: expiresAt,
    audiences: audience.audiences,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);

  const draft = await createNoticeDraft(parsed.data);
  if (!draft.ok) return bad(formData, draft.message);
  const id = draft.data.id;
  refresh(id);
  if (mode === 'draft') redirect(`/app/admin/notices/${id}`);

  const published = await publishNotice(id, mode === 'later' ? (publishAt ?? null) : null);
  // The draft is saved either way. If it could not be published, its page says so and lets the
  // author try again.
  redirect(published.ok ? `/app/admin/notices/${id}` : `/app/admin/notices/${id}?saved=draft`);
}

/** The notice's own home scope decides which permission to ask for (never the form). */
async function guardNotice(orgId: string, id: string) {
  const found = await getNotice(orgId, id);
  if (!found.ok || !found.data) return null;
  await requireModulePermission(orgId, found.data.location_id, 'communications', 'admin');
  return found.data;
}

export async function updateNoticeDraftAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  const notice = id ? await guardNotice(orgId, id) : null;
  if (!id || !notice) return bad(formData, BAD_ID);
  const zone = await noticeZone(orgId, notice.location_id);
  const publishAt = readTime(formData, 'publish_at', zone);
  const expiresAt = readTime(formData, 'expires_at', zone);
  if (publishAt === undefined || expiresAt === undefined) {
    return bad(formData, 'Enter a valid date and time.');
  }
  const parsed = noticeUpdateSchema.safeParse({
    title: str(formData, 'title'),
    body: str(formData, 'body'),
    urgency: str(formData, 'urgency') || 'normal',
    requires_acknowledgment: formData.get('requires_acknowledgment') === 'yes',
    publish_at: publishAt,
    expires_at: expiresAt,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateNoticeDraft(orgId, id, parsed.data);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Saved.');
}

export async function publishNoticeAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  const notice = id ? await guardNotice(orgId, id) : null;
  if (!id || !notice) return bad(formData, BAD_ID);
  const mode = str(formData, 'publish_mode') || 'now';
  let publishAt: string | null = null;
  if (mode === 'later') {
    const zone = await noticeZone(orgId, notice.location_id);
    const at = readTime(formData, 'publish_at', zone);
    if (!at) return bad(formData, 'Enter the date and time to publish.');
    publishAt = at;
  } else if (mode !== 'now') {
    return bad(formData, 'Choose when to publish.');
  }
  const result = await publishNotice(id, publishAt);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Published.');
}

export async function archiveNoticeAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  const notice = id ? await guardNotice(orgId, id) : null;
  if (!id || !notice) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await archiveNotice(id);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Archived. People no longer see it.');
}
