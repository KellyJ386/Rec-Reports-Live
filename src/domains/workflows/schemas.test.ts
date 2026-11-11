import { describe, expect, it } from 'vitest';
import {
  taskAssignSchema,
  taskCommentSchema,
  taskCreateSchema,
  taskReasonSchema,
  taskTemplateCreateSchema,
  taskTemplateUpdateSchema,
  workflowConditionSchema,
  workflowRuleCreateSchema,
  workflowRuleUpdateSchema,
  WORKFLOW_TRIGGER_TYPES,
} from './schemas';

const ORG = '00000000-0000-4000-8000-000000000001';
const LOC = '00000000-0000-4000-8000-000000000002';
const TASK = '00000000-0000-4000-8000-000000000003';
const PERSON = '00000000-0000-4000-8000-000000000004';
const TITLE = '00000000-0000-4000-8000-000000000005';
const TEMPLATE = '00000000-0000-4000-8000-000000000006';

const ok = (s: { safeParse: (v: unknown) => { success: boolean } }, v: unknown) =>
  s.safeParse(v).success;

describe('taskCreateSchema', () => {
  const valid = { organization_id: ORG, location_id: LOC, title: '  Close the rink gate  ' };

  it('accepts a minimal task and trims the title', () => {
    const r = taskCreateSchema.safeParse(valid);
    expect(r.success).toBe(true);
    if (r.success) {
      expect(r.data.title).toBe('Close the rink gate');
      expect(r.data.priority).toBe('normal');
    }
  });

  it('rejects an empty or 201-character title', () => {
    expect(ok(taskCreateSchema, { ...valid, title: '   ' })).toBe(false);
    expect(ok(taskCreateSchema, { ...valid, title: 'x'.repeat(201) })).toBe(false);
    expect(ok(taskCreateSchema, { ...valid, title: 'x'.repeat(200) })).toBe(true);
  });

  it('rejects priorities outside the four levels', () => {
    expect(ok(taskCreateSchema, { ...valid, priority: 'critical' })).toBe(false);
    expect(ok(taskCreateSchema, { ...valid, priority: 'urgent' })).toBe(true);
  });

  it('rejects instructions over 4000 characters and unknown keys such as status', () => {
    expect(ok(taskCreateSchema, { ...valid, instructions: 'x'.repeat(4001) })).toBe(false);
    expect(ok(taskCreateSchema, { ...valid, status: 'done' })).toBe(false);
  });

  it('rejects a due time that is not an ISO timestamp with an offset', () => {
    expect(ok(taskCreateSchema, { ...valid, due_at: '2027-05-01 10:00' })).toBe(false);
    expect(ok(taskCreateSchema, { ...valid, due_at: '2027-05-01T10:00:00Z' })).toBe(true);
  });
});

describe('task comment, assign and reason schemas', () => {
  it('limits a comment to 1-2000 characters after trimming', () => {
    expect(ok(taskCommentSchema, { task_id: TASK, body: 'Gate is fixed' })).toBe(true);
    expect(ok(taskCommentSchema, { task_id: TASK, body: '  ' })).toBe(false);
    expect(ok(taskCommentSchema, { task_id: TASK, body: 'x'.repeat(2001) })).toBe(false);
  });

  it('allows unassigning with nulls, and requires uuids', () => {
    expect(ok(taskAssignSchema, { task_id: TASK, person_id: null, job_title_id: null })).toBe(true);
    expect(ok(taskAssignSchema, { task_id: TASK, person_id: PERSON, job_title_id: null })).toBe(
      true,
    );
    expect(
      ok(taskAssignSchema, { task_id: TASK, person_id: 'not-a-uuid', job_title_id: null }),
    ).toBe(false);
    expect(ok(taskAssignSchema, { task_id: TASK, person_id: PERSON })).toBe(false);
  });

  it('allows a reason up to 2000 characters, or none', () => {
    expect(ok(taskReasonSchema, { task_id: TASK })).toBe(true);
    expect(ok(taskReasonSchema, { task_id: TASK, reason: 'Duplicate' })).toBe(true);
    expect(ok(taskReasonSchema, { task_id: TASK, reason: 'x'.repeat(2001) })).toBe(false);
  });
});

describe('workflowConditionSchema', () => {
  it('accepts the empty condition and up to 10 clauses', () => {
    expect(ok(workflowConditionSchema, {})).toBe(true);
    expect(
      ok(workflowConditionSchema, {
        all: [
          { field: 'urgency', op: 'eq', value: 'critical' },
          { field: 'space_id', op: 'in', value: ['a', 'b'] },
          { field: 'count', op: 'eq', value: 3 },
          { field: 'flag', op: 'eq', value: true },
        ],
      }),
    ).toBe(true);
    const ten = Array.from({ length: 10 }, () => ({ field: 'urgency', op: 'eq', value: 'high' }));
    expect(ok(workflowConditionSchema, { all: ten })).toBe(true);
    expect(ok(workflowConditionSchema, { all: [...ten, ten[0]] })).toBe(false);
  });

  it('rejects other operators, null values, nested values and bad field names', () => {
    expect(ok(workflowConditionSchema, { all: [{ field: 'urgency', op: 'gt', value: 1 }] })).toBe(
      false,
    );
    expect(
      ok(workflowConditionSchema, { all: [{ field: 'urgency', op: 'eq', value: null }] }),
    ).toBe(false);
    expect(
      ok(workflowConditionSchema, { all: [{ field: 'urgency', op: 'eq', value: { a: 1 } }] }),
    ).toBe(false);
    expect(ok(workflowConditionSchema, { all: [{ field: 'Urgency', op: 'eq', value: 'x' }] })).toBe(
      false,
    );
    expect(
      ok(workflowConditionSchema, { all: [{ field: 'urgency', op: 'eq', value: 'x', extra: 1 }] }),
    ).toBe(false);
  });

  it('limits in-lists to 1-50 scalars and strings to 200 characters', () => {
    expect(ok(workflowConditionSchema, { all: [{ field: 'f', op: 'in', value: [] }] })).toBe(false);
    expect(
      ok(workflowConditionSchema, {
        all: [{ field: 'f', op: 'in', value: Array.from({ length: 51 }, (_, i) => `v${i}`) }],
      }),
    ).toBe(false);
    expect(
      ok(workflowConditionSchema, { all: [{ field: 'f', op: 'eq', value: 'x'.repeat(201) }] }),
    ).toBe(false);
  });

  it('rejects a top-level key other than all', () => {
    expect(ok(workflowConditionSchema, { any: [{ field: 'f', op: 'eq', value: 'x' }] })).toBe(
      false,
    );
  });
});

describe('workflowRuleCreateSchema', () => {
  const valid = {
    organization_id: ORG,
    location_id: null,
    name: 'Clean after a failed check',
    event_type: 'checklist.item_failed',
    task_template_id: TEMPLATE,
  };

  it('accepts a rule on an allowed event type and defaults the condition to empty', () => {
    const r = workflowRuleCreateSchema.safeParse(valid);
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.condition).toEqual({});
  });

  it('rejects event types outside the pilot list, including task.created (no loops)', () => {
    expect(ok(workflowRuleCreateSchema, { ...valid, event_type: 'task.created' })).toBe(false);
    expect(ok(workflowRuleCreateSchema, { ...valid, event_type: 'membership.renewed' })).toBe(
      false,
    );
  });

  it('accepts every pilot trigger type, including task.overdue', () => {
    expect(WORKFLOW_TRIGGER_TYPES).toContain('task.overdue');
    for (const event_type of WORKFLOW_TRIGGER_TYPES) {
      expect(ok(workflowRuleCreateSchema, { ...valid, event_type }), event_type).toBe(true);
    }
  });

  it('rejects enabled on create: a new rule is always disabled', () => {
    expect(ok(workflowRuleCreateSchema, { ...valid, enabled: true })).toBe(false);
  });

  it('rejects a name longer than 200 characters', () => {
    expect(ok(workflowRuleCreateSchema, { ...valid, name: 'x'.repeat(201) })).toBe(false);
  });
});

describe('workflowRuleUpdateSchema', () => {
  it('accepts enabling a rule and rejects an empty update', () => {
    expect(ok(workflowRuleUpdateSchema, { enabled: true })).toBe(true);
    expect(ok(workflowRuleUpdateSchema, {})).toBe(false);
  });

  it('refuses to enable an archived rule in the same update', () => {
    expect(
      ok(workflowRuleUpdateSchema, { enabled: true, archived_at: '2027-05-01T10:00:00Z' }),
    ).toBe(false);
    expect(
      ok(workflowRuleUpdateSchema, { enabled: false, archived_at: '2027-05-01T10:00:00Z' }),
    ).toBe(true);
  });

  it('does not accept organization_id or location_id (immutable)', () => {
    expect(ok(workflowRuleUpdateSchema, { location_id: LOC })).toBe(false);
    expect(ok(workflowRuleUpdateSchema, { organization_id: ORG })).toBe(false);
  });
});

describe('task template schemas', () => {
  const base = {
    organization_id: ORG,
    location_id: LOC,
    title: 'Check the ice surface',
    default_priority: 'normal',
    due_offset_minutes: 30,
  };

  it('accepts an unassigned template and fills the nullable fields', () => {
    const r = taskTemplateCreateSchema.safeParse({ ...base, assign_to: 'none' });
    expect(r.success).toBe(true);
    if (r.success) {
      expect(r.data.assign_job_title_id).toBeNull();
      expect(r.data.assign_person_id).toBeNull();
    }
  });

  it('requires a job title exactly when the template assigns to a job title', () => {
    expect(
      ok(taskTemplateCreateSchema, { ...base, assign_to: 'job_title', assign_job_title_id: TITLE }),
    ).toBe(true);
    expect(ok(taskTemplateCreateSchema, { ...base, assign_to: 'job_title' })).toBe(false);
    expect(
      ok(taskTemplateCreateSchema, { ...base, assign_to: 'none', assign_job_title_id: TITLE }),
    ).toBe(false);
  });

  it('requires a person exactly when the template assigns to a person', () => {
    expect(
      ok(taskTemplateCreateSchema, { ...base, assign_to: 'person', assign_person_id: PERSON }),
    ).toBe(true);
    expect(ok(taskTemplateCreateSchema, { ...base, assign_to: 'person' })).toBe(false);
    expect(
      ok(taskTemplateCreateSchema, { ...base, assign_to: 'on_shift', assign_person_id: PERSON }),
    ).toBe(false);
  });

  it('keeps the due offset within a year either way', () => {
    expect(
      ok(taskTemplateCreateSchema, { ...base, due_offset_minutes: 525600, assign_to: 'none' }),
    ).toBe(true);
    expect(
      ok(taskTemplateCreateSchema, { ...base, due_offset_minutes: -525601, assign_to: 'none' }),
    ).toBe(false);
    expect(
      ok(taskTemplateCreateSchema, { ...base, due_offset_minutes: 1.5, assign_to: 'none' }),
    ).toBe(false);
  });

  it('rejects a bad default priority and an instruction over 4000 characters', () => {
    expect(
      ok(taskTemplateCreateSchema, { ...base, default_priority: 'asap', assign_to: 'none' }),
    ).toBe(false);
    expect(
      ok(taskTemplateCreateSchema, { ...base, instructions: 'x'.repeat(4001), assign_to: 'none' }),
    ).toBe(false);
  });

  it('update: rejects an empty update, and an assignment change must name all three fields', () => {
    expect(ok(taskTemplateUpdateSchema, {})).toBe(false);
    expect(ok(taskTemplateUpdateSchema, { archived_at: null })).toBe(true);
    expect(ok(taskTemplateUpdateSchema, { assign_to: 'none' })).toBe(false);
    expect(
      ok(taskTemplateUpdateSchema, {
        assign_to: 'person',
        assign_job_title_id: null,
        assign_person_id: PERSON,
      }),
    ).toBe(true);
    expect(
      ok(taskTemplateUpdateSchema, {
        assign_to: 'person',
        assign_job_title_id: TITLE,
        assign_person_id: PERSON,
      }),
    ).toBe(false);
  });

  it('update: does not accept location_id or organization_id', () => {
    expect(ok(taskTemplateUpdateSchema, { location_id: LOC })).toBe(false);
  });
});
