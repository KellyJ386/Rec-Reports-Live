// Pure logic for the workflows domain: labels, due-date buckets, the plain condition editor,
// due offsets, board filters and the failed-jobs view. No database access, so it is unit tested.
import { z } from 'zod';
import { TASK_PRIORITIES } from './schemas';

export type PermissionLevelName = 'none' | 'view' | 'edit' | 'admin';

// ---- labels ----

export const TASK_STATUSES = ['open', 'in_progress', 'done', 'cancelled'] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

export type TaskPriority = (typeof TASK_PRIORITIES)[number];

const STATUS_LABELS: Record<TaskStatus, string> = {
  open: 'Not started',
  in_progress: 'In progress',
  done: 'Done',
  cancelled: 'Cancelled',
};

const PRIORITY_LABELS: Record<TaskPriority, string> = {
  low: 'Low',
  normal: 'Normal',
  high: 'High',
  urgent: 'Urgent',
};

export function statusLabel(status: string): string {
  return STATUS_LABELS[status as TaskStatus] ?? status;
}

export function priorityLabel(priority: string): string {
  return PRIORITY_LABELS[priority as TaskPriority] ?? priority;
}

export const TASK_EVENT_LABELS: Record<string, string> = {
  created: 'Created',
  assigned: 'Assigned',
  started: 'Started',
  completed: 'Marked done',
  reopened: 'Reopened',
  cancelled: 'Cancelled',
  commented: 'Comment',
  escalated: 'Escalated',
};

export function taskEventLabel(kind: string): string {
  return TASK_EVENT_LABELS[kind] ?? kind;
}

// ---- what a person can do with a task ----

export type TaskActions = {
  start: boolean;
  complete: boolean;
  reopen: boolean;
  comment: boolean;
  assign: boolean;
  cancel: boolean;
};

/**
 * Which buttons to offer. This only decides what to show; the database refuses anything the
 * person is not allowed to do. `level` is their tasks permission at the task's location.
 */
export function availableTaskActions(status: string, level: PermissionLevelName): TaskActions {
  const edit = level === 'edit' || level === 'admin';
  const admin = level === 'admin';
  const live = status === 'open' || status === 'in_progress';
  return {
    start: edit && status === 'open',
    complete: edit && live,
    reopen: (edit && status === 'done') || (admin && status === 'cancelled'),
    comment: edit,
    assign: admin && live,
    cancel: admin && live,
  };
}

// ---- due date buckets ----

export type DueBucket = 'overdue' | 'today' | 'later' | 'none';

export const DUE_BUCKET_ORDER: readonly DueBucket[] = ['overdue', 'today', 'later', 'none'];

export const DUE_BUCKET_LABELS: Record<DueBucket, string> = {
  overdue: 'Overdue',
  today: 'Due today',
  later: 'Later',
  none: 'No due date',
};

/** The calendar date (YYYY-MM-DD) of an instant in a time zone. Unknown zones fall back to UTC. */
export function localDateKey(ms: number, timeZone: string): string {
  const format = (zone: string) =>
    new Intl.DateTimeFormat('en-US', {
      timeZone: zone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).formatToParts(new Date(ms));
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = format(timeZone);
  } catch {
    parts = format('UTC');
  }
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? '';
  return `${get('year')}-${get('month')}-${get('day')}`;
}

/**
 * Overdue: the due time has passed. Due today: not yet passed and on today's calendar date at
 * the task's location (so a 25-hour day in November and a 23-hour day in March still work).
 */
export function dueBucket(dueAt: string | null, nowMs: number, timeZone: string): DueBucket {
  if (!dueAt) return 'none';
  const due = Date.parse(dueAt);
  if (Number.isNaN(due)) return 'none';
  if (due < nowMs) return 'overdue';
  return localDateKey(due, timeZone) === localDateKey(nowMs, timeZone) ? 'today' : 'later';
}

export type BucketGroup<T> = { bucket: DueBucket; label: string; items: T[] };

/** Groups tasks into Overdue / Due today / Later / No due date, keeping the given order inside each group. */
export function groupByDueBucket<T>(
  items: readonly T[],
  getDueAt: (item: T) => string | null,
  getTimeZone: (item: T) => string,
  nowMs: number,
): BucketGroup<T>[] {
  const groups = new Map<DueBucket, T[]>();
  for (const item of items) {
    const bucket = dueBucket(getDueAt(item), nowMs, getTimeZone(item));
    const list = groups.get(bucket) ?? [];
    list.push(item);
    groups.set(bucket, list);
  }
  return DUE_BUCKET_ORDER.flatMap((bucket) => {
    const list = groups.get(bucket);
    return list && list.length > 0
      ? [{ bucket, label: DUE_BUCKET_LABELS[bucket], items: list }]
      : [];
  });
}

// ---- "my work" filter ----

const guidSchema = z.guid();

export type TitleScope = { job_title_id: string; location_id: string | null };

const MAX_TITLE_CLAUSES = 40;

/**
 * The PostgREST `or` filter for "tasks that are mine": assigned to me, or with nobody assigned
 * and either no job title or one of my job titles (held at the task's location, or everywhere),
 * or unassigned. The database has already narrowed the rows to what the person may see; an
 * admin can see more than their own work, so this narrows it again. Ids are validated here
 * because they are placed inside a filter string.
 */
export function myWorkFilter(personId: string, titles: readonly TitleScope[]): string | null {
  if (!guidSchema.safeParse(personId).success) return null;
  const parts = [
    `assigned_person_id.eq.${personId}`,
    'and(assigned_person_id.is.null,assigned_job_title_id.is.null)',
  ];
  const seen = new Set<string>();
  for (const t of titles) {
    if (!guidSchema.safeParse(t.job_title_id).success) continue;
    if (t.location_id !== null && !guidSchema.safeParse(t.location_id).success) continue;
    const key = `${t.job_title_id}:${t.location_id ?? ''}`;
    if (seen.has(key) || seen.size >= MAX_TITLE_CLAUSES) continue;
    seen.add(key);
    const where =
      t.location_id === null
        ? `assigned_job_title_id.eq.${t.job_title_id}`
        : `assigned_job_title_id.eq.${t.job_title_id},location_id.eq.${t.location_id}`;
    parts.push(`and(assigned_person_id.is.null,${where})`);
  }
  return parts.join(',');
}

// ---- who is a task assigned to ----

export function describeAssignee(
  personName: string | null,
  jobTitleName: string | null,
  status: string,
): string {
  if (personName && jobTitleName) return `${personName} (${jobTitleName})`;
  if (personName) return personName;
  if (jobTitleName) return `Anyone with the job title ${jobTitleName}`;
  return status === 'done' || status === 'cancelled' ? 'Nobody' : 'Nobody yet';
}

// ---- event types and the condition editor ----

/** Rule triggers, with a plain label for each. Must match private.workflow_trigger_types(). */
export const EVENT_TYPE_OPTIONS = [
  { value: 'booking.confirmed', label: 'A booking is confirmed' },
  { value: 'booking.rescheduled', label: 'A booking is moved to another time' },
  { value: 'booking.cancelled', label: 'A booking is cancelled' },
  { value: 'shift.uncovered', label: 'A shift has nobody to cover it' },
  { value: 'checklist.item_failed', label: 'A checklist item fails' },
  { value: 'checklist.completed', label: 'A checklist is finished' },
  { value: 'incident.submitted', label: 'An incident is reported' },
  { value: 'incident.reviewed', label: 'An incident is reviewed' },
  { value: 'task.overdue', label: 'A task is overdue' },
  { value: 'notice.published', label: 'A notice is published' },
] as const;

export function eventTypeLabel(type: string): string {
  return EVENT_TYPE_OPTIONS.find((o) => o.value === type)?.label ?? type;
}

export function isEventType(value: string): boolean {
  return EVENT_TYPE_OPTIONS.some((o) => o.value === value);
}

export type Scalar = string | number | boolean;
export type ConditionClause = { field: string; op: 'eq' | 'in'; value: Scalar | Scalar[] };
export type WorkflowCondition = Record<string, never> | { all: ConditionClause[] };

/** One row of the condition editor, as the form holds it. */
export type ClauseInput = { field: string; op: string; type: string; value: string };

export const MAX_CLAUSES = 10;
export const FORM_CLAUSE_ROWS = 3;
const FIELD_PATTERN = /^[a-z][a-z0-9_]{0,62}$/;
const MAX_TEXT_VALUE = 200;
const MAX_IN_VALUES = 50;

export const CLAUSE_OPS = [
  { value: 'eq', label: 'is' },
  { value: 'in', label: 'is one of (separate with commas)' },
] as const;

export const CLAUSE_TYPES = [
  { value: 'text', label: 'Text' },
  { value: 'number', label: 'Number' },
  { value: 'boolean', label: 'Yes or no (true / false)' },
] as const;

export const EMPTY_CLAUSE: ClauseInput = { field: '', op: 'eq', type: 'text', value: '' };

class ClauseError extends Error {}

function parseScalar(text: string, type: string, field: string): Scalar {
  if (type === 'number') {
    if (!/^-?\d+(\.\d+)?$/.test(text))
      throw new ClauseError(`"${text}" is not a number (${field}).`);
    return Number(text);
  }
  if (type === 'boolean') {
    const lower = text.toLowerCase();
    if (lower === 'true' || lower === 'yes') return true;
    if (lower === 'false' || lower === 'no') return false;
    throw new ClauseError(`For "${field}", type true or false.`);
  }
  if (text.length > MAX_TEXT_VALUE) {
    throw new ClauseError(`A value for "${field}" is longer than ${MAX_TEXT_VALUE} characters.`);
  }
  return text;
}

/**
 * Turns the editor rows into the stored condition: `{}` when there are no rows, else
 * `{"all": [...]}`. Exactly the shape private.validate_workflow_condition accepts (1 to 10
 * clauses; "is" takes one value; "is one of" takes 1 to 50; scalars only). Blank rows are skipped.
 */
export function conditionFromForm(
  rows: readonly ClauseInput[],
): { ok: true; condition: WorkflowCondition } | { ok: false; message: string } {
  const clauses: ConditionClause[] = [];
  try {
    for (const row of rows) {
      const field = row.field.trim();
      const value = row.value.trim();
      if (field === '' && value === '') continue;
      if (!FIELD_PATTERN.test(field)) {
        return {
          ok: false,
          message:
            'Field names use lowercase letters, numbers and underscores, for example space_id.',
        };
      }
      if (value === '') return { ok: false, message: `Give a value for "${field}".` };
      if (row.op === 'in') {
        const parts = value
          .split(',')
          .map((p) => p.trim())
          .filter((p) => p !== '');
        if (parts.length < 1 || parts.length > MAX_IN_VALUES) {
          return { ok: false, message: `Give 1 to ${MAX_IN_VALUES} values for "${field}".` };
        }
        clauses.push({
          field,
          op: 'in',
          value: parts.map((p) => parseScalar(p, row.type, field)),
        });
      } else if (row.op === 'eq') {
        clauses.push({ field, op: 'eq', value: parseScalar(value, row.type, field) });
      } else {
        return { ok: false, message: 'Pick "is" or "is one of".' };
      }
    }
  } catch (e) {
    if (e instanceof ClauseError) return { ok: false, message: e.message };
    throw e;
  }
  if (clauses.length > MAX_CLAUSES) {
    return { ok: false, message: `Use at most ${MAX_CLAUSES} conditions.` };
  }
  return { ok: true, condition: clauses.length === 0 ? {} : { all: clauses } };
}

function scalarType(v: unknown): 'text' | 'number' | 'boolean' | null {
  if (typeof v === 'string') return 'text';
  if (typeof v === 'number') return 'number';
  if (typeof v === 'boolean') return 'boolean';
  return null;
}

/**
 * The editor rows for a stored condition, or null when the editor cannot show it faithfully
 * (a list that mixes types, a value with a comma or spaces around it, an empty text value).
 * The check is a round trip: the rows must produce exactly the stored condition again.
 */
export function conditionToForm(condition: unknown): ClauseInput[] | null {
  if (condition === null || typeof condition !== 'object' || Array.isArray(condition)) return null;
  const keys = Object.keys(condition);
  if (keys.length === 0) return [];
  const all = (condition as { all?: unknown }).all;
  if (keys.length !== 1 || keys[0] !== 'all' || !Array.isArray(all)) return null;
  const rows: ClauseInput[] = [];
  for (const clause of all) {
    if (clause === null || typeof clause !== 'object') return null;
    const { field, op, value } = clause as { field?: unknown; op?: unknown; value?: unknown };
    if (typeof field !== 'string') return null;
    if (op === 'eq') {
      const type = scalarType(value);
      if (!type) return null;
      rows.push({ field, op: 'eq', type, value: String(value) });
    } else if (op === 'in' && Array.isArray(value) && value.length > 0) {
      const type = scalarType(value[0]);
      if (!type || value.some((v) => scalarType(v) !== type)) return null;
      rows.push({ field, op: 'in', type, value: value.map(String).join(', ') });
    } else {
      return null;
    }
  }
  const back = conditionFromForm(rows);
  if (!back.ok || JSON.stringify(back.condition) !== JSON.stringify(condition)) return null;
  return rows;
}

/** One plain sentence per clause, for lists. */
export function describeCondition(condition: unknown): string {
  const rows = conditionToForm(condition);
  if (rows === null) return 'A condition set in an earlier version';
  if (rows.length === 0) return 'Every time it happens';
  return rows
    .map((r) => (r.op === 'in' ? `${r.field} is one of ${r.value}` : `${r.field} is ${r.value}`))
    .join(' and ');
}

// ---- due offsets on templates ----

export const OFFSET_UNITS = [
  { value: 'minutes', label: 'minutes', factor: 1 },
  { value: 'hours', label: 'hours', factor: 60 },
  { value: 'days', label: 'days', factor: 1440 },
] as const;

export const OFFSET_DIRECTIONS = [
  { value: 'before', label: 'before' },
  { value: 'after', label: 'after' },
] as const;

const MAX_OFFSET_MINUTES = 525600;

export type OffsetInput = { amount: string; unit: string; direction: string };

/** Blank amount = no due time (null). Otherwise minutes, negative for "before". */
export function offsetFromForm(
  input: OffsetInput,
): { ok: true; minutes: number | null } | { ok: false; message: string } {
  const text = input.amount.trim();
  if (text === '') return { ok: true, minutes: null };
  if (!/^\d{1,7}$/.test(text)) {
    return { ok: false, message: 'Enter the time as a whole number, for example 2.' };
  }
  const unit = OFFSET_UNITS.find((u) => u.value === input.unit);
  if (!unit) return { ok: false, message: 'Pick minutes, hours or days.' };
  if (input.direction !== 'before' && input.direction !== 'after') {
    return { ok: false, message: 'Pick before or after.' };
  }
  const minutes = Number(text) * unit.factor;
  if (minutes > MAX_OFFSET_MINUTES) return { ok: false, message: 'That is more than 365 days.' };
  return { ok: true, minutes: input.direction === 'before' && minutes !== 0 ? -minutes : minutes };
}

export function offsetToForm(minutes: number | null): OffsetInput {
  if (minutes === null) return { amount: '', unit: 'hours', direction: 'before' };
  const abs = Math.abs(minutes);
  const direction = minutes < 0 ? 'before' : 'after';
  if (abs !== 0 && abs % 1440 === 0) return { amount: String(abs / 1440), unit: 'days', direction };
  if (abs !== 0 && abs % 60 === 0) return { amount: String(abs / 60), unit: 'hours', direction };
  return { amount: String(abs), unit: 'minutes', direction };
}

export function describeOffset(minutes: number | null): string {
  if (minutes === null) return 'No due time';
  if (minutes === 0) return 'Due at the event time';
  const form = offsetToForm(minutes);
  const n = Number(form.amount);
  const unit = n === 1 ? form.unit.replace(/s$/, '') : form.unit;
  return `Due ${n} ${unit} ${form.direction} the event time`;
}

export const OVERDUE_RULE_TEMPLATE_MESSAGE =
  'A rule for overdue tasks needs a task template that is due at least 1 minute after the event. Change the template, or pick another one.';

/**
 * A rule on `task.overdue` makes a task about a task that is already late. The database refuses a
 * template that is due at or before the event time (offset 0 or below), because that task would
 * be overdue the moment it is made and the rule would loop. No due time at all (null) is fine.
 * Returns the message to show, or null when the pair is allowed.
 */
export function overdueRuleTemplateProblem(
  eventType: string | undefined,
  dueOffsetMinutes: number | null | undefined,
): string | null {
  if (eventType !== 'task.overdue') return null;
  if (dueOffsetMinutes === null || dueOffsetMinutes === undefined) return null;
  return dueOffsetMinutes < 1 ? OVERDUE_RULE_TEMPLATE_MESSAGE : null;
}

export const ASSIGN_TO_OPTIONS = [
  { value: 'none', label: 'Nobody (anyone at the location can pick it up)' },
  { value: 'job_title', label: 'People with a job title' },
  { value: 'person', label: 'One person' },
  { value: 'on_shift', label: 'Whoever is on shift (not working yet: stays unassigned for now)' },
] as const;

// ---- board filters ----

export const BOARD_STATUS_OPTIONS = [
  { value: 'active', label: 'Not finished' },
  { value: 'open', label: 'Not started' },
  { value: 'in_progress', label: 'In progress' },
  { value: 'done', label: 'Done' },
  { value: 'cancelled', label: 'Cancelled' },
  { value: 'all', label: 'All' },
] as const;

export type BoardStatus = (typeof BOARD_STATUS_OPTIONS)[number]['value'];

export type BoardFilters = {
  status: BoardStatus;
  /** Free-text name search for the assignee; resolved to people by the page. */
  assigneeSearch: string;
  /** 'nobody' = no person assigned. */
  assignee: 'any' | 'nobody' | 'search';
  jobTitleId: string | null;
  overdue: boolean;
};

type Params = Record<string, string | string[] | undefined>;

function first(value: string | string[] | undefined): string {
  return (Array.isArray(value) ? value[0] : value) ?? '';
}

export function parseBoardFilters(params: Params): BoardFilters {
  const status =
    BOARD_STATUS_OPTIONS.find((o) => o.value === first(params.status))?.value ?? 'active';
  const title = guidSchema.safeParse(first(params.title).trim());
  const assignee = first(params.assignee);
  const search = first(params.aq).trim().slice(0, 100);
  return {
    status,
    assigneeSearch: search,
    assignee: assignee === 'nobody' ? 'nobody' : search !== '' ? 'search' : 'any',
    jobTitleId: title.success ? title.data : null,
    overdue: first(params.overdue) === '1',
  };
}

// ---- failed jobs ----

const UUID_IN_TEXT = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

/**
 * A short, safe label for why a job failed: the part before the first colon, without ids or
 * digits runs, at most 60 characters. Never the whole message, never any payload content.
 */
export function errorClass(lastError: string | null | undefined): string {
  if (!lastError) return 'Unknown error';
  const line = (lastError.split(/\r?\n/)[0] ?? '').split(':')[0] ?? '';
  const cleaned = line
    .replace(UUID_IN_TEXT, '')
    .replace(/\d{4,}/g, '')
    .replace(/[^A-Za-z0-9 _.-]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 60);
  return cleaned === '' ? 'Unknown error' : cleaned;
}

/** How many times a failed job may be retried by hand (private.outbox_max_manual_retries()). */
export const MAX_MANUAL_RETRIES = 3;

/** True while a stopped job may still be retried by hand. */
export function canRetryJob(job: { status: string; manual_retries: number }): boolean {
  return job.status === 'dead' && job.manual_retries < MAX_MANUAL_RETRIES;
}

export function jobStateLabel(status: string): string {
  if (status === 'dead') return 'Failed. It stopped trying.';
  if (status === 'pending') return 'Failing. It will try again.';
  if (status === 'processing') return 'Running again';
  return status;
}
