'use server';

import { revalidatePath } from 'next/cache';
import { requireOrgMember } from '@/lib/auth';
import {
  BAD_ID,
  activeOrgId,
  bad,
  good,
  guid,
  type AdminFormState,
} from '@/experiences/admin/actions/helpers';
import { acknowledgeNotice } from '@/domains/communications';

/** "I have read this". The database checks the person is in the audience and the notice is live. */
export async function acknowledgeNoticeAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'notice_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await acknowledgeNotice(id);
  if (!result.ok) return bad(formData, result.message);
  revalidatePath('/app/notices');
  revalidatePath(`/app/notices/${id}`);
  revalidatePath('/app');
  return good('Thank you. Your answer is saved.');
}
