'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireOrgMember } from '@/lib/auth';
import {
  activeOrgId,
  bad,
  str,
  zodProblem,
  type AdminFormState,
} from '@/experiences/admin/actions/helpers';
import { messageSendSchema, parseRecipientIds, sendMessage } from '@/domains/communications';

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
  revalidatePath('/app/messages');
  revalidatePath('/app');
  redirect('/app/messages?view=sent');
}
