'use server';

import { revalidatePath } from 'next/cache';
import { requireOrgMember } from '@/lib/auth';
import { BAD_ID, activeOrgId, bad, fromResult, guid, type AdminFormState } from './helpers';
import { retryFailedJob } from '@/domains/workflows';

/** Puts a failed job back in the queue. The database checks the permission and that it failed. */
export async function retryJobAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'job_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await retryFailedJob(id);
  if (result.ok) revalidatePath('/app/admin/jobs');
  return fromResult(formData, result, 'Queued to run again.');
}
