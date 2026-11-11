'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireModulePermission, requireOrgMember } from '@/lib/auth';
import { zonedLocalToUtc } from '@/lib/time';
import {
  BAD_ID,
  NOT_CONFIRMED,
  activeOrgId,
  bad,
  confirmed,
  fromResult,
  guid,
  optionalGuid,
  str,
  zodProblem,
  type AdminFormState,
} from '@/experiences/admin/actions/helpers';
import { getLocation } from '@/domains/organizations';
import {
  addTaskComment,
  assignTask,
  cancelTask,
  completeTask,
  createTask,
  getTask,
  reopenTask,
  startTask,
  taskAssignSchema,
  taskCommentSchema,
  taskCompleteSchema,
  taskCreateSchema,
  taskReasonSchema,
} from '@/domains/workflows';

function refresh(taskId: string) {
  revalidatePath('/app/my-work');
  revalidatePath(`/app/tasks/${taskId}`);
  revalidatePath('/app/admin/tasks');
  revalidatePath('/app');
}

export async function startTaskAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'task_id');
  if (!id) return bad(formData, BAD_ID);
  const result = await startTask(id);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Started.');
}

export async function completeTaskAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const parsed = taskCompleteSchema.safeParse({
    task_id: str(formData, 'task_id').trim(),
    note: str(formData, 'note'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await completeTask(parsed.data);
  if (result.ok) refresh(parsed.data.task_id);
  return fromResult(formData, result, 'Marked done.');
}

export async function reopenTaskAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const parsed = taskReasonSchema.safeParse({
    task_id: str(formData, 'task_id').trim(),
    reason: str(formData, 'reason'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await reopenTask(parsed.data);
  if (result.ok) refresh(parsed.data.task_id);
  return fromResult(formData, result, 'Reopened.');
}

export async function commentTaskAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const parsed = taskCommentSchema.safeParse({
    task_id: str(formData, 'task_id').trim(),
    body: str(formData, 'body'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await addTaskComment(parsed.data);
  if (result.ok) refresh(parsed.data.task_id);
  return fromResult(formData, result, 'Comment added.');
}

/** A manager's action on one task: the task's own location decides which permission to ask for. */
async function requireTaskAdmin(orgId: string, taskId: string): Promise<boolean> {
  const task = await getTask(orgId, taskId);
  if (!task.ok || !task.data) return false;
  await requireModulePermission(orgId, task.data.location_id, 'tasks', 'admin');
  return true;
}

export async function assignTaskAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'task_id');
  if (!id) return bad(formData, BAD_ID);
  if (!(await requireTaskAdmin(orgId, id))) return bad(formData, BAD_ID);
  const to = str(formData, 'to');
  const personId = to === 'person' ? optionalGuid(formData, 'person_id') : null;
  const titleId = to === 'title' ? optionalGuid(formData, 'job_title_id') : null;
  if (to !== 'person' && to !== 'title' && to !== 'nobody') {
    return bad(formData, 'Choose who gets this task.');
  }
  if ((to === 'person' && !personId) || (to === 'title' && !titleId)) {
    return bad(formData, to === 'person' ? 'Choose a person.' : 'Choose a job title.');
  }
  const parsed = taskAssignSchema.safeParse({
    task_id: id,
    person_id: personId ?? null,
    job_title_id: titleId ?? null,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await assignTask(parsed.data);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Saved.');
}

export async function cancelTaskAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireOrgMember(orgId);
  const id = guid(formData, 'task_id');
  if (!id) return bad(formData, BAD_ID);
  if (!(await requireTaskAdmin(orgId, id))) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const parsed = taskReasonSchema.safeParse({ task_id: id, reason: str(formData, 'reason') });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await cancelTask(parsed.data);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Cancelled.');
}

export async function createTaskAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const membership = await requireOrgMember(orgId);
  const locationId = guid(formData, 'location_id');
  if (!locationId) return bad(formData, 'Choose a location.');
  await requireModulePermission(orgId, locationId, 'tasks', 'edit');

  const location = await getLocation(orgId, locationId);
  if (!location.ok || !location.data) return bad(formData, 'That location could not be found.');

  const dueText = str(formData, 'due').trim();
  let dueAt: string | null = null;
  if (dueText !== '') {
    dueAt = zonedLocalToUtc(dueText, location.data.timezone);
    if (!dueAt) return bad(formData, 'Enter a valid due date and time.');
  }
  const spaceId = optionalGuid(formData, 'space_id');
  if (spaceId === undefined) return bad(formData, 'Pick a space from the list.');

  const to = str(formData, 'to') || 'nobody';
  let personId: string | null = null;
  let titleId: string | null = null;
  if (to === 'me') {
    personId = membership.personId;
    if (!personId) return bad(formData, 'You do not have a staff profile here.');
  } else if (to === 'person') {
    const p = optionalGuid(formData, 'person_id');
    if (!p) return bad(formData, 'Choose a person.');
    personId = p;
  } else if (to === 'title') {
    const t = optionalGuid(formData, 'job_title_id');
    if (!t) return bad(formData, 'Choose a job title.');
    titleId = t;
  } else if (to !== 'nobody') {
    return bad(formData, 'Choose who gets this task.');
  }

  const parsed = taskCreateSchema.safeParse({
    organization_id: orgId,
    location_id: locationId,
    title: str(formData, 'title'),
    instructions: str(formData, 'instructions'),
    due_at: dueAt,
    priority: str(formData, 'priority') || 'normal',
    space_id: spaceId,
    assigned_person_id: personId,
    assigned_job_title_id: titleId,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createTask(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  refresh(result.data.id);
  redirect(`/app/tasks/${result.data.id}`);
}
