// Input validation for the staffing domain (positions, qualifications, schedules, shifts,
// templates, availability, time off, swaps and claims). Mirrors
// supabase/migrations/20261113000100_staff_scheduling.sql. The database stays the authority;
// these schemas reject bad input before it reaches an RPC. Strict objects: unknown keys are
// rejected.
import { z } from 'zod';

const name = z.string().trim().min(1, 'Enter a name').max(100, 'Use 100 characters or fewer');
const note = (max: number) =>
  z
    .string()
    .trim()
    .max(max, `Use ${max} characters or fewer`)
    .transform((v) => (v === '' ? null : v));
const isoDateTime = z.iso.datetime({ offset: true });
const localDate = z.iso.date();
const timeOfDay = z
  .string()
  .regex(/^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/, 'Enter a time like 09:00');
const endTimeOfDay = z
  .string()
  .regex(/^(([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?|24:00(:00)?)$/, 'Enter a time like 17:00');

const MAX_SHIFT_MS = 24 * 60 * 60 * 1000;

export const positionSaveSchema = z.strictObject({
  organization_id: z.uuid(),
  location_id: z.uuid().nullable(),
  name,
  qualification_ids: z.array(z.uuid()).max(20, 'At most 20 qualifications').nullable().optional(),
  position_id: z.uuid().nullable().optional(),
});

export const qualificationSaveSchema = z.strictObject({
  organization_id: z.uuid(),
  name,
  qualification_id: z.uuid().nullable().optional(),
});

export const personQualificationSchema = z
  .strictObject({
    organization_id: z.uuid(),
    person_id: z.uuid(),
    qualification_id: z.uuid(),
    valid_from: localDate.nullable(),
    expires_on: localDate.nullable(),
  })
  .refine((v) => !v.valid_from || !v.expires_on || v.valid_from <= v.expires_on, {
    message: 'The last valid day must not be before the first',
    path: ['expires_on'],
  });

export const templateSaveSchema = z.strictObject({
  organization_id: z.uuid(),
  location_id: z.uuid(),
  name,
  span_days: z.union([z.literal(1), z.literal(7)]).optional(),
  template_id: z.uuid().nullable().optional(),
});

export const templateItemSchema = z.strictObject({
  template_id: z.uuid(),
  position_id: z.uuid(),
  day_offset: z.number().int().min(0).max(6),
  start_time: timeOfDay,
  duration_minutes: z.number().int().min(15, 'At least 15 minutes').max(1440, 'At most 24 hours'),
  assigned_person_id: z.uuid().nullable().optional(),
  notes: note(1000).nullable().optional(),
});

export const scheduleCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  location_id: z.uuid(),
  week_start: localDate,
});

function endsAfterStart(v: { starts_at?: string | null; ends_at?: string | null }): boolean {
  if (!v.starts_at || !v.ends_at) return true;
  const span = Date.parse(v.ends_at) - Date.parse(v.starts_at);
  return span > 0 && span <= MAX_SHIFT_MS;
}
const SPAN_MESSAGE = 'A shift must end after it starts and last at most 24 hours';

export const shiftCreateSchema = z
  .strictObject({
    schedule_id: z.uuid(),
    position_id: z.uuid(),
    starts_at: isoDateTime,
    ends_at: isoDateTime,
    assigned_person_id: z.uuid().nullable().optional(),
    notes: note(1000).nullable().optional(),
    override: z.boolean().optional(),
  })
  .refine(endsAfterStart, { message: SPAN_MESSAGE, path: ['ends_at'] });

export const shiftUpdateSchema = z
  .strictObject({
    shift_id: z.uuid(),
    position_id: z.uuid().nullable().optional(),
    starts_at: isoDateTime.nullable().optional(),
    ends_at: isoDateTime.nullable().optional(),
    // null keeps the notes; '' clears them.
    notes: z.string().trim().max(1000, 'Use 1000 characters or fewer').nullable().optional(),
    override: z.boolean().optional(),
  })
  .refine(endsAfterStart, { message: SPAN_MESSAGE, path: ['ends_at'] });

export const shiftAssignSchema = z.strictObject({
  shift_id: z.uuid(),
  person_id: z.uuid().nullable(),
  override: z.boolean().optional(),
});

export const templateApplySchema = z.strictObject({
  schedule_id: z.uuid(),
  template_id: z.uuid(),
  first_day: z.number().int().min(0).max(6).optional(),
});

export const swapRequestSchema = z.strictObject({
  shift_id: z.uuid(),
  to_person_id: z.uuid(),
  counter_shift_id: z.uuid().nullable().optional(),
  note: note(500).nullable().optional(),
});

export const dropRequestSchema = z.strictObject({
  shift_id: z.uuid(),
  note: note(500).nullable().optional(),
});

export const decisionSchema = z.strictObject({
  id: z.uuid(),
  approve: z.boolean(),
  override: z.boolean().optional(),
});

export const availabilitySchema = z
  .strictObject({
    organization_id: z.uuid(),
    day_of_week: z.number().int().min(1).max(7),
    start_time: timeOfDay,
    end_time: endTimeOfDay,
    kind: z.enum(['available', 'unavailable', 'preferred']),
    effective_from: localDate.nullable().optional(),
    effective_to: localDate.nullable().optional(),
  })
  .refine((v) => v.start_time < v.end_time, {
    message: 'The end must be after the start',
    path: ['end_time'],
  })
  .refine((v) => !v.effective_from || !v.effective_to || v.effective_from <= v.effective_to, {
    message: 'The last day must not be before the first',
    path: ['effective_to'],
  });

export const AVAILABILITY_KINDS = ['available', 'unavailable', 'preferred'] as const;

export const timeOffRequestSchema = z
  .strictObject({
    organization_id: z.uuid(),
    starts_on: localDate,
    ends_on: localDate,
    reason: note(500).nullable().optional(),
  })
  .refine((v) => v.starts_on <= v.ends_on, {
    message: 'The last day must not be before the first',
    path: ['ends_on'],
  })
  .refine((v) => (Date.parse(v.ends_on) - Date.parse(v.starts_on)) / 86400000 <= 365, {
    message: 'Choose at most a year',
    path: ['ends_on'],
  });

export const staffingSettingsSchema = z.strictObject({
  auto_approve_swaps: z.boolean(),
  first_come_open_shifts: z.boolean(),
});

export type PositionSave = z.infer<typeof positionSaveSchema>;
export type QualificationSave = z.infer<typeof qualificationSaveSchema>;
export type PersonQualificationInput = z.infer<typeof personQualificationSchema>;
export type TemplateSave = z.infer<typeof templateSaveSchema>;
export type TemplateItemInput = z.infer<typeof templateItemSchema>;
export type ScheduleCreate = z.infer<typeof scheduleCreateSchema>;
export type ShiftCreate = z.infer<typeof shiftCreateSchema>;
export type ShiftUpdate = z.infer<typeof shiftUpdateSchema>;
export type ShiftAssign = z.infer<typeof shiftAssignSchema>;
export type TemplateApply = z.infer<typeof templateApplySchema>;
export type SwapRequest = z.infer<typeof swapRequestSchema>;
export type DropRequest = z.infer<typeof dropRequestSchema>;
export type Decision = z.infer<typeof decisionSchema>;
export type AvailabilityInput = z.infer<typeof availabilitySchema>;
export type TimeOffRequestInput = z.infer<typeof timeOffRequestSchema>;
export type StaffingSettings = z.infer<typeof staffingSettingsSchema>;
