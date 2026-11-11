'use server';

import { revalidatePath } from 'next/cache';
import { requireOrgMember } from '@/lib/auth';
import {
  BAD_ID,
  activeOrgId,
  bad,
  fromResult,
  good,
  guid,
  type AdminFormState,
} from '@/experiences/admin/actions/helpers';
import {
  deletePushSubscription,
  markAllNotificationsRead,
  markNotificationsRead,
  PUSH_NOT_SUPPORTED_MESSAGE,
  pushSubscriptionSaveSchema,
  savePushSubscription,
  setChannelEnabled,
} from '@/domains/communications';

function refresh() {
  revalidatePath('/app/notifications');
  revalidatePath('/app');
}

export async function markNotificationReadAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'notification_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await markNotificationsRead([id]);
  if (result.ok) refresh();
  return fromResult(formData, result, 'Marked as read.');
}

export async function markAllNotificationsReadAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const result = await markAllNotificationsRead(orgId);
  if (result.ok) refresh();
  return fromResult(formData, result, 'All marked as read.');
}

/** Email and push on or off. In-app cannot be turned off, and critical notices ignore these. */
export async function saveChannelSettingsAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const membership = await requireOrgMember(orgId);
  if (!membership.personId) return bad(formData, 'You do not have a staff profile here.');
  for (const channel of ['email', 'push'] as const) {
    const result = await setChannelEnabled(
      orgId,
      membership.personId,
      channel,
      formData.get(channel) === 'yes',
    );
    if (!result.ok) return bad(formData, result.message);
  }
  refresh();
  return good('Saved.');
}

export type DeviceResult = { ok: boolean; message: string };

/** Called by the "Turn on notifications on this device" button with the browser's subscription. */
export async function saveDeviceAction(input: {
  endpoint: string;
  p256dh: string;
  auth: string;
  userAgent?: string;
}): Promise<DeviceResult> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const parsed = pushSubscriptionSaveSchema.safeParse({
    organization_id: orgId,
    endpoint: input?.endpoint,
    p256dh: input?.p256dh,
    auth_secret: input?.auth,
    user_agent: typeof input?.userAgent === 'string' ? input.userAgent.slice(0, 300) : null,
  });
  if (!parsed.success) {
    const unsupported = parsed.error.issues.some(
      (i) => i.path[0] === 'endpoint' && i.message === PUSH_NOT_SUPPORTED_MESSAGE,
    );
    return {
      ok: false,
      message: unsupported
        ? PUSH_NOT_SUPPORTED_MESSAGE
        : 'This device could not be set up for notifications.',
    };
  }
  const result = await savePushSubscription(parsed.data);
  if (!result.ok) return { ok: false, message: result.message };
  refresh();
  return { ok: true, message: 'Notifications are on for this device.' };
}

export async function removeDeviceAction(input: { endpoint: string }): Promise<DeviceResult> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  if (typeof input?.endpoint !== 'string' || !/^https:\/\/\S{1,1990}$/.test(input.endpoint)) {
    return { ok: false, message: 'This device could not be found.' };
  }
  const result = await deletePushSubscription(orgId, input.endpoint);
  if (!result.ok) return { ok: false, message: result.message };
  refresh();
  return { ok: true, message: 'Notifications are off for this device.' };
}
