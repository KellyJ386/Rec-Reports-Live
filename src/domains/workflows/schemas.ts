// Input validation for the workflows domain: tasks (create, start, complete,
// reopen, cancel, assign, comment), task templates and workflow rules. Mirrors
// supabase/migrations/20261112000300_tasks_and_workflows.sql (the CHECK constraints,
// the RPC validation and the tenant grants). The database stays the authority;
// these schemas reject bad input before it reaches an RPC.
//
// Strict objects: unknown keys are rejected, so a client cannot send columns the
// database does not let it write (for example workflow_rules.enabled on create).
import { z } from 'zod';

const trimmedName = (max: number) => z.string().trim().min(1, 'Enter a name').max(max);

// Empty after trimming means "no text": stored as null, as the RPCs do.
const optionalText = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .transform((v) => (v === '' ? null : v));

const isoDateTime = z.iso.datetime({ offset: true });
const archivedAt = isoDateTime.nullable();
const nonEmpty = <T extends z.ZodTypeAny>(s: T) =>
  s.refine((v) => Object.keys(v as object).length > 0, 'Nothing to update');

export const TASK_PRIORITIES = ['low', 'normal', 'high', 'urgent'] as const;
export const prioritySchema = z.enum(TASK_PRIORITIES);

// Who a template assigns to. on_shift is a Phase 3 placeholder: unassigned until the
// staff schedule exists.
export const ASSIGN_TO_VALUES = ['none', 'job_title', 'person', 'on_shift'] as const;
export const assignToSchema = z.enum(ASSIGN_TO_VALUES);

// Event types a workflow rule may react to. Same list as private.workflow_trigger_types().
// No task.* event except task.overdue, so a rule cannot create tasks in a loop.
export const WORKFLOW_TRIGGER_TYPES = [
  'booking.confirmed',
  'booking.rescheduled',
  'booking.cancelled',
  'shift.uncovered',
  'checklist.item_failed',
  'checklist.completed',
  'incident.submitted',
  'incident.reviewed',
  'task.overdue',
  'notice.published',
] as const;
export const workflowTriggerTypeSchema = z.enum(WORKFLOW_TRIGGER_TYPES);

// Mirrors private.validate_workflow_condition: {} or {"all": [1-10 clauses]}, each clause
// exactly {field, op, value}; op eq takes a scalar, op in takes 1-50 scalars. A scalar is a
// number, a boolean or a string of at most 200 characters. Nothing else.
const CONDITION_FIELD = /^[a-z][a-z0-9_]{0,62}$/;
const MAX_CONDITION_BYTES = 8192;
const scalarSchema = z.union([z.number().finite(), z.boolean(), z.string().max(200)]);
const clauseSchema = z.union([
  z.strictObject({
    field: z.string().regex(CONDITION_FIELD, 'Use a lowercase payload field name'),
    op: z.literal('eq'),
    value: scalarSchema,
  }),
  z.strictObject({
    field: z.string().regex(CONDITION_FIELD, 'Use a lowercase payload field name'),
    op: z.literal('in'),
    value: z.array(scalarSchema).min(1, 'Add at least one value').max(50, 'At most 50 values'),
  }),
]);
export const workflowConditionSchema = z
  .union([z.strictObject({}), z.strictObject({ all: z.array(clauseSchema).min(1).max(10) })])
  .refine(
    (c) => new TextEncoder().encode(JSON.stringify(c)).length <= MAX_CONDITION_BYTES,
    'The condition is too large',
  );

// Task templates: the assignment fields must agree with assign_to, as the table CHECKs say:
// (assign_to = 'job_title') = (assign_job_title_id is not null), and the same for person.
function assignmentAgrees(v: {
  assign_to: (typeof ASSIGN_TO_VALUES)[number];
  assign_job_title_id?: string | null;
  assign_person_id?: string | null;
}): boolean {
  return (
    (v.assign_to === 'job_title') === (v.assign_job_title_id != null) &&
    (v.assign_to === 'person') === (v.assign_person_id != null)
  );
}
const ASSIGNMENT_MESSAGE = 'Pick a job title or a person only when the template assigns to that';

const templateFields = {
  title: trimmedName(200),
  instructions: optionalText(4000),
  default_priority: prioritySchema,
  due_offset_minutes: z
    .number()
    .int()
    .min(-525600, 'Offset is out of range')
    .max(525600, 'Offset is out of range')
    .nullable(),
  assign_to: assignToSchema,
  assign_job_title_id: z.uuid().nullable(),
  assign_person_id: z.uuid().nullable(),
};

export const taskTemplateCreateSchema = z
  .strictObject({
    organization_id: z.uuid(),
    // null = usable at every location of the organization
    location_id: z.uuid().nullable(),
    ...templateFields,
    instructions: templateFields.instructions.nullable().optional(),
    default_priority: templateFields.default_priority.default('normal'),
    due_offset_minutes: templateFields.due_offset_minutes.optional(),
    assign_to: templateFields.assign_to.default('none'),
    assign_job_title_id: templateFields.assign_job_title_id.optional(),
    assign_person_id: templateFields.assign_person_id.optional(),
  })
  .transform((v) => ({
    ...v,
    assign_job_title_id: v.assign_job_title_id ?? null,
    assign_person_id: v.assign_person_id ?? null,
    due_offset_minutes: v.due_offset_minutes ?? null,
  }))
  .refine(assignmentAgrees, { message: ASSIGNMENT_MESSAGE, path: ['assign_to'] });

// location_id and organization_id are fixed at creation. The three assignment fields
// travel together: the table CHECK needs all of them to judge the pair, so an update
// that names any of them must name all three.
const ASSIGNMENT_KEYS = ['assign_to', 'assign_job_title_id', 'assign_person_id'] as const;
export const taskTemplateUpdateSchema = nonEmpty(
  z
    .strictObject({
      title: templateFields.title,
      instructions: templateFields.instructions.nullable(),
      default_priority: templateFields.default_priority,
      due_offset_minutes: templateFields.due_offset_minutes,
      assign_to: templateFields.assign_to,
      assign_job_title_id: templateFields.assign_job_title_id,
      assign_person_id: templateFields.assign_person_id,
      archived_at: archivedAt,
    })
    .partial()
    .superRefine((v, ctx) => {
      const present = ASSIGNMENT_KEYS.filter((k) => v[k] !== undefined);
      if (present.length === 0) return;
      if (present.length !== ASSIGNMENT_KEYS.length) {
        ctx.addIssue({
          code: 'custom',
          message: 'Send assign_to, assign_job_title_id and assign_person_id together',
          path: ['assign_to'],
        });
        return;
      }
      if (
        !assignmentAgrees({
          assign_to: v.assign_to!,
          assign_job_title_id: v.assign_job_title_id,
          assign_person_id: v.assign_person_id,
        })
      ) {
        ctx.addIssue({ code: 'custom', message: ASSIGNMENT_MESSAGE, path: ['assign_to'] });
      }
    }),
);

// Workflow rules are always created disabled (trigger). Enabling is an update, and the
// database refuses it when the template is archived; that check needs the template row.
export const workflowRuleCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  location_id: z.uuid().nullable(),
  name: trimmedName(200),
  event_type: workflowTriggerTypeSchema,
  condition: workflowConditionSchema.default({}),
  task_template_id: z.uuid(),
});

export const workflowRuleUpdateSchema = nonEmpty(
  z
    .strictObject({
      name: trimmedName(200),
      event_type: workflowTriggerTypeSchema,
      condition: workflowConditionSchema,
      task_template_id: z.uuid(),
      enabled: z.boolean(),
      archived_at: archivedAt,
    })
    .partial()
    .refine((v) => !(v.archived_at != null && v.enabled === true), {
      message: 'An archived rule cannot be enabled',
      path: ['enabled'],
    }),
);

// Tasks. Writes go through RPCs (no tenant table grant), so these are the RPC inputs.
export const taskCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  location_id: z.uuid(),
  title: trimmedName(200),
  instructions: optionalText(4000).optional(),
  due_at: isoDateTime.nullable().optional(),
  priority: prioritySchema.default('normal'),
  space_id: z.uuid().nullable().optional(),
  assigned_person_id: z.uuid().nullable().optional(),
  assigned_job_title_id: z.uuid().nullable().optional(),
});

export const taskIdSchema = z.strictObject({ task_id: z.uuid() });

export const taskCompleteSchema = z.strictObject({
  task_id: z.uuid(),
  note: optionalText(2000).optional(),
});

// reopen and cancel take an optional reason, stored as text in the task history.
export const taskReasonSchema = z.strictObject({
  task_id: z.uuid(),
  reason: optionalText(2000).optional(),
});

// Both ids may be null: null person = unassigned, null job title = no title. The RPC
// checks that the person may be given tasks here and rejects a change that does nothing.
export const taskAssignSchema = z.strictObject({
  task_id: z.uuid(),
  person_id: z.uuid().nullable(),
  job_title_id: z.uuid().nullable(),
});

export const taskCommentSchema = z.strictObject({
  task_id: z.uuid(),
  body: z
    .string()
    .trim()
    .min(1, 'Write a comment')
    .max(2000, 'A comment can be at most 2000 characters'),
});

export type TaskTemplateCreate = z.infer<typeof taskTemplateCreateSchema>;
export type TaskTemplateUpdate = z.infer<typeof taskTemplateUpdateSchema>;
export type WorkflowRuleCreate = z.infer<typeof workflowRuleCreateSchema>;
export type WorkflowRuleUpdate = z.infer<typeof workflowRuleUpdateSchema>;
export type TaskCreate = z.infer<typeof taskCreateSchema>;
export type TaskComplete = z.infer<typeof taskCompleteSchema>;
export type TaskReason = z.infer<typeof taskReasonSchema>;
export type TaskAssign = z.infer<typeof taskAssignSchema>;
export type TaskComment = z.infer<typeof taskCommentSchema>;
