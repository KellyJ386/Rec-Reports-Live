'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireModulePermission } from '@/lib/auth';
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
} from './helpers';
import {
  MAX_CLAUSES,
  conditionFromForm,
  createWorkflowRule,
  getTaskTemplate,
  getWorkflowRule,
  overdueRuleTemplateProblem,
  setWorkflowRuleArchived,
  setWorkflowRuleEnabled,
  updateWorkflowRule,
  workflowRuleCreateSchema,
  workflowRuleUpdateSchema,
  type ClauseInput,
} from '@/domains/workflows';

/** The condition editor rows (c0_field, c0_op, c0_type, c0_value, c1_field, ...). */
function clauseRows(formData: FormData): ClauseInput[] {
  const rows: ClauseInput[] = [];
  for (let i = 0; i < MAX_CLAUSES; i++) {
    rows.push({
      field: str(formData, `c${i}_field`),
      op: str(formData, `c${i}_op`) || 'eq',
      type: str(formData, `c${i}_type`) || 'text',
      value: str(formData, `c${i}_value`),
    });
  }
  return rows;
}

function refresh(id?: string) {
  revalidatePath('/app/admin/workflow-rules');
  if (id) revalidatePath(`/app/admin/workflow-rules/${id}`);
}

export async function createWorkflowRuleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = optionalGuid(formData, 'location_id');
  if (locationId === undefined) return bad(formData, 'Pick a location from the list.');
  await requireModulePermission(orgId, locationId, 'tasks', 'admin');
  const condition = conditionFromForm(clauseRows(formData));
  if (!condition.ok) return bad(formData, condition.message);
  const templateId = guid(formData, 'task_template_id');
  if (!templateId) return bad(formData, 'Choose the task template this rule makes.');
  const parsed = workflowRuleCreateSchema.safeParse({
    organization_id: orgId,
    location_id: locationId,
    name: str(formData, 'name'),
    event_type: str(formData, 'event_type'),
    condition: condition.condition,
    task_template_id: templateId,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const template = await getTaskTemplate(orgId, templateId);
  if (template.ok && template.data) {
    const problem = overdueRuleTemplateProblem(
      parsed.data.event_type,
      template.data.due_offset_minutes,
    );
    if (problem) return bad(formData, problem);
  }
  const result = await createWorkflowRule(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  refresh();
  redirect(`/app/admin/workflow-rules/${result.data.id}`);
}

async function guardRule(orgId: string, id: string): Promise<boolean> {
  const found = await getWorkflowRule(orgId, id);
  if (!found.ok || !found.data) return false;
  await requireModulePermission(orgId, found.data.location_id, 'tasks', 'admin');
  return true;
}

export async function updateWorkflowRuleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id || !(await guardRule(orgId, id))) return bad(formData, BAD_ID);
  const templateId = guid(formData, 'task_template_id');
  if (!templateId) return bad(formData, 'Choose the task template this rule makes.');
  // A condition the editor cannot show is left exactly as it is stored.
  let condition: ReturnType<typeof conditionFromForm> | null = null;
  if (str(formData, 'condition_kept') !== 'yes') {
    condition = conditionFromForm(clauseRows(formData));
    if (!condition.ok) return bad(formData, condition.message);
  }
  const parsed = workflowRuleUpdateSchema.safeParse({
    name: str(formData, 'name'),
    event_type: str(formData, 'event_type'),
    task_template_id: templateId,
    ...(condition && condition.ok ? { condition: condition.condition } : {}),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  // The event type may be unchanged (not in the form data of every caller): use the stored one.
  const stored = await getWorkflowRule(orgId, id);
  const eventType = parsed.data.event_type ?? (stored.ok ? stored.data?.event_type : undefined);
  const template = await getTaskTemplate(orgId, templateId);
  if (template.ok && template.data) {
    const problem = overdueRuleTemplateProblem(eventType, template.data.due_offset_minutes);
    if (problem) return bad(formData, problem);
  }
  const result = await updateWorkflowRule(orgId, id, parsed.data);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Saved.');
}

export async function enableWorkflowRuleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id || !(await guardRule(orgId, id))) return bad(formData, BAD_ID);
  const result = await setWorkflowRuleEnabled(orgId, id, true);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Switched on. This rule now makes tasks.');
}

export async function disableWorkflowRuleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id || !(await guardRule(orgId, id))) return bad(formData, BAD_ID);
  const result = await setWorkflowRuleEnabled(orgId, id, false);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Switched off. This rule no longer makes tasks.');
}

export async function archiveWorkflowRuleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id || !(await guardRule(orgId, id))) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await setWorkflowRuleArchived(orgId, id, true);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Archived and switched off.');
}

export async function restoreWorkflowRuleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id || !(await guardRule(orgId, id))) return bad(formData, BAD_ID);
  const result = await setWorkflowRuleArchived(orgId, id, false);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Restored. It is still switched off.');
}
