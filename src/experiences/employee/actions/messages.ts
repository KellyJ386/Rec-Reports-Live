'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireOrgMember } from '@/lib/auth';
import {
  BAD_ID,
  activeOrgId,
  bad,
  guid,
  str,
  zodProblem,
  type AdminFormState,
} from '@/experiences/admin/actions/helpers';
import {
  markMessageRead,
  messageSendSchema,
  parseRecipientIds,
  sendMessage,
} from '@/domains/communications';

/** Sends a message. Who may be written to is decided by the database (people the sender can see). */
export async function sendMessageAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const parsed = messageSendSchema.safeParse({
    organization_id: orgId,
    recipient_person_ids: parseRecipientIds(str(formData, 'to')),
    body: str(formData, 'body'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await sendMessage(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  // Replying counts as having read it. Best effort: the message is already sent.
  const replyTo = guid(formData, 'reply_to');
  if (replyTo) await markMessageRead(replyTo);
  revalidatePath('/app/messages');
  revalidatePath('/app');
  redirect('/app/messages?view=sent');
}

/** The "Mark as read" button on a message. POST only; the database keeps the first read time. */
export async function markMessageReadAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'message_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await markMessageRead(id);
  if (!result.ok) return bad(formData, result.message);
  revalidatePath('/app/messages');
  revalidatePath(`/app/messages/${id}`);
  revalidatePath('/app');
  return { ok: true, message: 'Marked as read.' };
}
