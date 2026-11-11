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
  createTaskTemplate,
  getTaskTemplate,
  offsetFromForm,
  setTaskTemplateArchived,
  taskTemplateCreateSchema,
  taskTemplateUpdateSchema,
  updateTaskTemplate,
} from '@/domains/workflows';

type Fields =
  | { ok: false; state: AdminFormState }
  | {
      ok: true;
      fields: {
        title: string;
        instructions: string;
        default_priority: string;
        due_offset_minutes: number | null;
        assign_to: string;
        assign_job_title_id: string | null;
        assign_person_id: string | null;
      };
    };

/** The fields a template create and a template edit share, read from the form. */
function readFields(formData: FormData): Fields {
  const offset = offsetFromForm({
    amount: str(formData, 'offset_amount'),
    unit: str(formData, 'offset_unit'),
    direction: str(formData, 'offset_direction'),
  });
  if (!offset.ok) return { ok: false, state: bad(formData, offset.message) };
  const assignTo = str(formData, 'assign_to') || 'none';
  const titleId = assignTo === 'job_title' ? optionalGuid(formData, 'assign_job_title_id') : null;
  const personId = assignTo === 'person' ? optionalGuid(formData, 'assign_person_id') : null;
  if (assignTo === 'job_title' && !titleId) {
    return { ok: false, state: bad(formData, 'Choose a job title.') };
  }
  if (assignTo === 'person' && !personId) {
    return { ok: false, state: bad(formData, 'Choose a person.') };
  }
  return {
    ok: true,
    fields: {
      title: str(formData, 'title'),
      instructions: str(formData, 'instructions'),
      default_priority: str(formData, 'default_priority') || 'normal',
      due_offset_minutes: offset.minutes,
      assign_to: assignTo,
      assign_job_title_id: titleId ?? null,
      assign_person_id: personId ?? null,
    },
  };
}

function refresh(id?: string) {
  revalidatePath('/app/admin/task-templates');
  if (id) revalidatePath(`/app/admin/task-templates/${id}`);
}

export async function createTaskTemplateAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const locationId = optionalGuid(formData, 'location_id');
  if (locationId === undefined) return bad(formData, 'Pick a location from the list.');
  await requireModulePermission(orgId, locationId, 'tasks', 'admin');
  const read = readFields(formData);
  if (!read.ok) return read.state;
  const parsed = taskTemplateCreateSchema.safeParse({
    organization_id: orgId,
    location_id: locationId,
    ...read.fields,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createTaskTemplate(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  refresh();
  redirect(`/app/admin/task-templates/${result.data.id}`);
}

/** The template's own location decides which permission to ask for (never the form). */
async function guardTemplate(orgId: string, id: string): Promise<boolean> {
  const found = await getTaskTemplate(orgId, id);
  if (!found.ok || !found.data) return false;
  await requireModulePermission(orgId, found.data.location_id, 'tasks', 'admin');
  return true;
}

export async function updateTaskTemplateAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id || !(await guardTemplate(orgId, id))) return bad(formData, BAD_ID);
  const read = readFields(formData);
  if (!read.ok) return read.state;
  const parsed = taskTemplateUpdateSchema.safeParse(read.fields);
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateTaskTemplate(orgId, id, parsed.data);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Saved.');
}

export async function archiveTaskTemplateAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id || !(await guardTemplate(orgId, id))) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await setTaskTemplateArchived(orgId, id, true);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Archived. Rules that use it stop making tasks.');
}

export async function restoreTaskTemplateAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id || !(await guardTemplate(orgId, id))) return bad(formData, BAD_ID);
  const result = await setTaskTemplateArchived(orgId, id, false);
  if (result.ok) refresh(id);
  return fromResult(formData, result, 'Restored.');
}
