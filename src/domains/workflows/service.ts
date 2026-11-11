// Workflows domain services: tasks, task templates, workflow rules and the failed-jobs list.
// Everything goes through the caller's session client, so RLS decides what is visible. Task
// state changes use only the database RPCs (create_task, start_task, ...); this file never
// updates a task or inserts a task_events row directly. Templates and rules are plain
// configuration rows with their own policies.
import { createClient } from '@/lib/supabase/server';
import type { Json, Tables } from '@/lib/supabase/database.types';
import {
  fail,
  failure,
  ok,
  requireChanged,
  type DbErrorLike,
  type ErrorContext,
  type Result,
} from '@/lib/db-errors';
import { fetchAllRows, fetchClampedPage, type Paged } from '@/lib/paging';
import { errorClass, myWorkFilter, type TitleScope } from './logic';
import type {
  TaskAssign,
  TaskComment,
  TaskComplete,
  TaskCreate,
  TaskReason,
  TaskTemplateCreate,
  TaskTemplateUpdate,
  WorkflowRuleCreate,
  WorkflowRuleUpdate,
} from './schemas';

const TASK_COLUMNS =
  'id, organization_id, location_id, space_id, title, instructions, status, priority, due_at, assigned_person_id, assigned_job_title_id, created_by_person_id, completed_by_person_id, completed_at, cancelled_at, created_at';
const TEMPLATE_COLUMNS =
  'id, organization_id, location_id, title, instructions, default_priority, due_offset_minutes, assign_to, assign_job_title_id, assign_person_id, archived_at, created_at';
const RULE_COLUMNS =
  'id, organization_id, location_id, name, event_type, condition, task_template_id, enabled, archived_at, created_at';

export type TaskRow = Pick<
  Tables<'tasks'>,
  | 'id'
  | 'organization_id'
  | 'location_id'
  | 'space_id'
  | 'title'
  | 'instructions'
  | 'status'
  | 'priority'
  | 'due_at'
  | 'assigned_person_id'
  | 'assigned_job_title_id'
  | 'created_by_person_id'
  | 'completed_by_person_id'
  | 'completed_at'
  | 'cancelled_at'
  | 'created_at'
>;

export type TaskHistoryRow = Pick<
  Tables<'task_events'>,
  | 'id'
  | 'kind'
  | 'actor_person_id'
  | 'from_status'
  | 'to_status'
  | 'assigned_person_id'
  | 'assigned_job_title_id'
  | 'body'
  | 'created_at'
>;

export type TaskTemplate = Pick<
  Tables<'task_templates'>,
  | 'id'
  | 'organization_id'
  | 'location_id'
  | 'title'
  | 'instructions'
  | 'default_priority'
  | 'due_offset_minutes'
  | 'assign_to'
  | 'assign_job_title_id'
  | 'assign_person_id'
  | 'archived_at'
  | 'created_at'
>;

export type WorkflowRule = Pick<
  Tables<'workflow_rules'>,
  | 'id'
  | 'organization_id'
  | 'location_id'
  | 'name'
  | 'event_type'
  | 'condition'
  | 'task_template_id'
  | 'enabled'
  | 'archived_at'
  | 'created_at'
>;

export type TemplateChoice = Pick<
  Tables<'task_templates'>,
  'id' | 'title' | 'location_id' | 'archived_at'
>;

/** A job that failed. The payload and the raw error text never leave this file. */
export type FailedJob = {
  id: string;
  type: string;
  location_id: string | null;
  status: string;
  attempts: number;
  created_at: string;
  next_attempt_at: string;
  retried_at: string | null;
  errorClass: string;
};

/** Assignment rows differ only in the 'nothing to change' text, which the shared map words for roles. */
function taskFailure(error: DbErrorLike, context: ErrorContext = {}) {
  if ((error.message ?? '').toLowerCase().includes('nothing to change')) {
    return fail('That is already how it is assigned.');
  }
  return failure(error, context);
}

// ---- tasks: reading ----

/**
 * The person's own work: tasks assigned to them, to one of their job titles (held at the task's
 * location or everywhere), or to nobody. RLS has already limited the rows to what they may see;
 * an admin sees more than that, so the filter narrows it again. 'open' is not started or in
 * progress, soonest due first; 'done' is the most recently finished first.
 */
export async function listMyWork(
  orgId: string,
  personId: string,
  titles: readonly TitleScope[],
  view: 'open' | 'done',
  page: number,
): Promise<Result<Paged<TaskRow>>> {
  const filter = myWorkFilter(personId, titles);
  if (!filter) return fail('Your work could not be loaded.');
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) => {
    let q = supabase
      .from('tasks')
      .select(TASK_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId)
      .or(filter);
    if (view === 'done') {
      q = q.eq('status', 'done').order('completed_at', { ascending: false });
    } else {
      q = q
        .in('status', ['open', 'in_progress'])
        .order('due_at', { ascending: true, nullsFirst: false });
    }
    return q.order('created_at', { ascending: false }).order('id').range(from, to);
  });
}

export async function countMyOpenTasks(
  orgId: string,
  personId: string,
  titles: readonly TitleScope[],
): Promise<Result<number>> {
  const filter = myWorkFilter(personId, titles);
  if (!filter) return fail('Your work could not be counted.');
  const supabase = await createClient();
  const { count, error } = await supabase
    .from('tasks')
    .select('id', { count: 'exact', head: true })
    .eq('organization_id', orgId)
    .in('status', ['open', 'in_progress'])
    .or(filter);
  if (error) return failure(error);
  return ok(count ?? 0);
}

export async function getTask(orgId: string, id: string): Promise<Result<TaskRow | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('tasks')
    .select(TASK_COLUMNS)
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

/** The whole history of one task, oldest first. Follows the task: if the task is hidden, so is this. */
export async function listTaskHistory(
  orgId: string,
  taskId: string,
): Promise<Result<TaskHistoryRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<TaskHistoryRow>((from, to) =>
    supabase
      .from('task_events')
      .select(
        'id, kind, actor_person_id, from_status, to_status, assigned_person_id, assigned_job_title_id, body, created_at',
      )
      .eq('organization_id', orgId)
      .eq('task_id', taskId)
      .order('created_at')
      .order('id')
      .range(from, to),
  );
}

export type BoardQuery = {
  locationId: string;
  status: 'active' | 'open' | 'in_progress' | 'done' | 'cancelled' | 'all';
  assignee: { kind: 'any' } | { kind: 'nobody' } | { kind: 'people'; ids: string[] };
  jobTitleId: string | null;
  overdue: boolean;
};

/** One page of the tasks at a location, for managers (RLS shows every task there to tasks = admin). */
export async function listBoardTasks(
  orgId: string,
  query: BoardQuery,
  page: number,
): Promise<Result<Paged<TaskRow>>> {
  if (query.assignee.kind === 'people' && query.assignee.ids.length === 0) {
    return ok({ rows: [], total: 0, page: 1, pageSize: 25 });
  }
  const supabase = await createClient();
  const nowIso = new Date().toISOString();
  return fetchClampedPage(page, (from, to) => {
    let q = supabase
      .from('tasks')
      .select(TASK_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('location_id', query.locationId);
    if (query.status === 'active') q = q.in('status', ['open', 'in_progress']);
    else if (query.status !== 'all') q = q.eq('status', query.status);
    if (query.assignee.kind === 'nobody') q = q.is('assigned_person_id', null);
    if (query.assignee.kind === 'people') q = q.in('assigned_person_id', query.assignee.ids);
    if (query.jobTitleId) q = q.eq('assigned_job_title_id', query.jobTitleId);
    if (query.overdue) q = q.in('status', ['open', 'in_progress']).lt('due_at', nowIso);
    return q
      .order('due_at', { ascending: true, nullsFirst: false })
      .order('created_at', { ascending: false })
      .order('id')
      .range(from, to);
  });
}

// ---- tasks: changing (database RPCs only) ----

export async function createTask(input: TaskCreate): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('create_task', {
    p_organization_id: input.organization_id,
    p_location_id: input.location_id,
    p_title: input.title,
    p_instructions: input.instructions ?? null,
    p_due_at: input.due_at ?? null,
    p_priority: input.priority,
    p_space_id: input.space_id ?? null,
    p_assigned_person_id: input.assigned_person_id ?? null,
    p_assigned_job_title_id: input.assigned_job_title_id ?? null,
  });
  if (error) return taskFailure(error);
  if (!data) return fail('The task was not created.');
  return ok({ id: data });
}

export async function startTask(taskId: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('start_task', { p_task_id: taskId });
  return error ? taskFailure(error) : ok(null);
}

export async function completeTask(input: TaskComplete): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('complete_task', {
    p_task_id: input.task_id,
    p_note: input.note ?? null,
  });
  return error ? taskFailure(error) : ok(null);
}

export async function reopenTask(input: TaskReason): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('reopen_task', {
    p_task_id: input.task_id,
    p_reason: input.reason ?? null,
  });
  return error ? taskFailure(error) : ok(null);
}

export async function assignTask(input: TaskAssign): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('assign_task', {
    p_task_id: input.task_id,
    p_person_id: input.person_id,
    p_job_title_id: input.job_title_id,
  });
  return error ? taskFailure(error) : ok(null);
}

export async function cancelTask(input: TaskReason): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('cancel_task', {
    p_task_id: input.task_id,
    p_reason: input.reason ?? null,
  });
  return error ? taskFailure(error) : ok(null);
}

export async function addTaskComment(input: TaskComment): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('add_task_comment', {
    p_task_id: input.task_id,
    p_body: input.body,
  });
  return error ? taskFailure(error) : ok(null);
}

// ---- task templates ----

export async function listTaskTemplates(
  orgId: string,
  options: { includeArchived: boolean },
  page: number,
): Promise<Result<Paged<TaskTemplate>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) => {
    let q = supabase
      .from('task_templates')
      .select(TEMPLATE_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId);
    if (!options.includeArchived) q = q.is('archived_at', null);
    return q.order('title').order('id').range(from, to);
  });
}

/** Every template (small configuration list) for a picker. Archived ones are included so a rule can still name its own. */
export async function listTemplateChoices(orgId: string): Promise<Result<TemplateChoice[]>> {
  const supabase = await createClient();
  return fetchAllRows<TemplateChoice>((from, to) =>
    supabase
      .from('task_templates')
      .select('id, title, location_id, archived_at')
      .eq('organization_id', orgId)
      .order('title')
      .order('id')
      .range(from, to),
  );
}

export async function getTaskTemplate(
  orgId: string,
  id: string,
): Promise<Result<TaskTemplate | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('task_templates')
    .select(TEMPLATE_COLUMNS)
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

export async function createTaskTemplate(
  input: TaskTemplateCreate,
): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.from('task_templates').insert(input).select('id').single();
  if (error)
    return failure(error, { foreignKey: 'That job title, person or location is not available.' });
  return ok({ id: data.id });
}

export async function updateTaskTemplate(
  orgId: string,
  id: string,
  patch: TaskTemplateUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('task_templates')
    .update(patch)
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error, { foreignKey: 'That job title or person is not available.' });
  return requireChanged(data);
}

export async function setTaskTemplateArchived(
  orgId: string,
  id: string,
  archived: boolean,
): Promise<Result<number>> {
  return updateTaskTemplate(orgId, id, { archived_at: archived ? new Date().toISOString() : null });
}

// ---- workflow rules ----

export async function listWorkflowRules(
  orgId: string,
  options: { includeArchived: boolean },
  page: number,
): Promise<Result<Paged<WorkflowRule>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) => {
    let q = supabase
      .from('workflow_rules')
      .select(RULE_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId);
    if (!options.includeArchived) q = q.is('archived_at', null);
    return q.order('name').order('id').range(from, to);
  });
}

export async function getWorkflowRule(
  orgId: string,
  id: string,
): Promise<Result<WorkflowRule | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('workflow_rules')
    .select(RULE_COLUMNS)
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

/** The database always stores a new rule switched off, whatever is sent. */
export async function createWorkflowRule(
  input: WorkflowRuleCreate,
): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('workflow_rules')
    .insert({ ...input, condition: input.condition as Json })
    .select('id')
    .single();
  if (error)
    return failure(error, { foreignKey: 'That task template or location is not available.' });
  return ok({ id: data.id });
}

export async function updateWorkflowRule(
  orgId: string,
  id: string,
  patch: WorkflowRuleUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { condition, ...rest } = patch;
  const { data, error } = await supabase
    .from('workflow_rules')
    .update(condition === undefined ? rest : { ...rest, condition: condition as Json })
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error, { foreignKey: 'That task template is not available.' });
  return requireChanged(data);
}

export async function setWorkflowRuleEnabled(
  orgId: string,
  id: string,
  enabled: boolean,
): Promise<Result<number>> {
  return updateWorkflowRule(orgId, id, { enabled });
}

/** Archiving also switches the rule off (an archived rule cannot be on). */
export async function setWorkflowRuleArchived(
  orgId: string,
  id: string,
  archived: boolean,
): Promise<Result<number>> {
  return updateWorkflowRule(
    orgId,
    id,
    archived ? { enabled: false, archived_at: new Date().toISOString() } : { archived_at: null },
  );
}

// ---- failed jobs ----

/** Jobs that gave up (dead) or failed and will try again. Newest change first. */
export async function listFailedJobs(
  orgId: string,
  page: number,
): Promise<Result<Paged<FailedJob>>> {
  const supabase = await createClient();
  const res = await fetchClampedPage(page, (from, to) =>
    supabase
      .from('outbox_events')
      .select(
        'id, type, location_id, status, attempts, created_at, next_attempt_at, retried_at, last_error',
        { count: 'exact' },
      )
      .eq('organization_id', orgId)
      .or('status.eq.dead,and(status.eq.pending,attempts.gt.0)')
      .order('updated_at', { ascending: false })
      .order('id')
      .range(from, to),
  );
  if (!res.ok) return res;
  return ok({
    ...res.data,
    rows: res.data.rows.map((r) => ({
      id: r.id,
      type: r.type,
      location_id: r.location_id,
      status: r.status,
      attempts: r.attempts,
      created_at: r.created_at,
      next_attempt_at: r.next_attempt_at,
      retried_at: r.retried_at,
      errorClass: errorClass(r.last_error),
    })),
  });
}

/** Put a dead job back in the queue. The database checks the permission and that it is dead. */
export async function retryFailedJob(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('retry_dead_outbox_event', { p_id: id });
  return error ? failure(error) : ok(null);
}
