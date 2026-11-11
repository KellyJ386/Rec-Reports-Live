'use server';

import { revalidatePath } from 'next/cache';
import { requireOrgMember } from '@/lib/auth';
import {
  BAD_ID,
  activeOrgId,
  bad,
  fromResult,
  guid,
  str,
  zodProblem,
  type AdminFormState,
} from '@/experiences/admin/actions/helpers';
import {
  addAvailability,
  availabilitySchema,
  cancelClaim,
  cancelSwap,
  cancelTimeOff,
  dropRequestSchema,
  removeAvailability,
  requestClaim,
  requestDrop,
  requestSwap,
  requestTimeOff,
  respondToSwap,
  swapRequestSchema,
  timeOffRequestSchema,
} from '@/domains/staffing';

function refresh() {
  revalidatePath('/app/schedule', 'layout');
  revalidatePath('/app');
}

async function member(): Promise<string> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  return orgId;
}

export async function requestSwapAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  await member();
  const parsed = swapRequestSchema.safeParse({
    shift_id: str(formData, 'shift_id').trim(),
    to_person_id: str(formData, 'to_person_id').trim(),
    note: str(formData, 'note'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await requestSwap(parsed.data);
  if (result.ok) refresh();
  return fromResult(formData, result, 'Swap offered. They will be told.');
}

export async function requestDropAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  await member();
  const parsed = dropRequestSchema.safeParse({
    shift_id: str(formData, 'shift_id').trim(),
    note: str(formData, 'note'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await requestDrop(parsed.data);
  if (result.ok) refresh();
  return fromResult(formData, result, 'Asked a manager to take you off this shift.');
}

export async function respondSwapAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  await member();
  const id = guid(formData, 'swap_id');
  const answer = str(formData, 'answer');
  if (!id || (answer !== 'accept' && answer !== 'decline')) return bad(formData, BAD_ID);
  const result = await respondToSwap(id, answer === 'accept');
  if (!result.ok) return bad(formData, result.message);
  refresh();
  const text =
    result.data === 'approved'
      ? 'Swap done. The shifts are switched.'
      : result.data === 'accepted'
        ? 'Accepted. A manager still has to approve it.'
        : 'Declined.';
  return { ok: true, message: text };
}

export async function cancelSwapAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  await member();
  const id = guid(formData, 'swap_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await cancelSwap(id);
  if (result.ok) refresh();
  return fromResult(formData, result, 'Cancelled.');
}

export async function requestClaimAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  await member();
  const id = guid(formData, 'shift_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await requestClaim(id);
  if (result.ok) refresh();
  return fromResult(
    formData,
    result,
    'Asked for this shift. A manager will decide, unless it goes to the first person to ask.',
  );
}

export async function cancelClaimAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  await member();
  const id = guid(formData, 'claim_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await cancelClaim(id);
  if (result.ok) refresh();
  return fromResult(formData, result, 'Cancelled.');
}

export async function requestTimeOffAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await member();
  const parsed = timeOffRequestSchema.safeParse({
    organization_id: orgId,
    starts_on: str(formData, 'starts_on'),
    ends_on: str(formData, 'ends_on') || str(formData, 'starts_on'),
    reason: str(formData, 'reason'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await requestTimeOff(parsed.data);
  if (result.ok) revalidatePath('/app/schedule/time-off');
  return fromResult(formData, result, 'Time off requested. A manager will decide.');
}

export async function cancelTimeOffAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  await member();
  const id = guid(formData, 'time_off_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await cancelTimeOff(id);
  if (result.ok) revalidatePath('/app/schedule/time-off');
  return fromResult(formData, result, 'Cancelled.');
}

export async function addAvailabilityAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await member();
  const day = Number(str(formData, 'day_of_week'));
  const parsed = availabilitySchema.safeParse({
    organization_id: orgId,
    day_of_week: day,
    start_time: str(formData, 'start_time'),
    end_time: str(formData, 'end_time'),
    kind: str(formData, 'kind'),
    effective_from: str(formData, 'effective_from') || null,
    effective_to: str(formData, 'effective_to') || null,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await addAvailability(parsed.data);
  if (result.ok) revalidatePath('/app/schedule/availability');
  return fromResult(formData, result, 'Saved.');
}

export async function removeAvailabilityAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  await member();
  const id = guid(formData, 'availability_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await removeAvailability(id);
  if (result.ok) revalidatePath('/app/schedule/availability');
  return fromResult(formData, result, 'Removed.');
}
