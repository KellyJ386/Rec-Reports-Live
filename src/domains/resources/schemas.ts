// Input validation for the resources domain (spaces, kinds, hours, closures).
// Mirrors supabase/migrations/20261111000100_organizations_and_resources.sql.
// Strict objects: id, organization_id (on update), created_at and updated_at are rejected.
// Cross-row rules (sub-space depth, overlapping hours, a booking's location) are
// enforced by the database; these schemas check the shape of one input only.
import { z } from 'zod';

const name = (max: number) => z.string().trim().min(1, 'Enter a name').max(max);

const optionalText = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .transform((v) => (v === '' ? null : v))
    .nullable();

const archivedAt = z.iso.datetime({ offset: true }).nullable();
const nonEmpty = <T extends z.ZodTypeAny>(s: T) =>
  s.refine((v) => Object.keys(v as object).length > 0, 'Nothing to update');

// 'HH:MM' or 'HH:MM:SS'. closes_at may also be '24:00' (end of day).
const TIME = /^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/;
const timeOfDay = z.string().regex(TIME, 'Use a time like 09:30');
const closingTime = z
  .string()
  .regex(
    /^(24:00(:00)?|([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?)$/,
    'Use a time like 21:00, or 24:00 for midnight',
  );
const toSeconds = (t: string) => {
  if (t.startsWith('24:00')) return 86400;
  const [h, m, s = '0'] = t.split(':');
  return Number(h) * 3600 + Number(m) * 60 + Number(s);
};
const isoDate = z.iso.date();
const dateRangeOk = (v: { effective_from?: string | null; effective_to?: string | null }) =>
  !v.effective_from || !v.effective_to || v.effective_to >= v.effective_from;

// Space kinds: key is set once (immutable), name and order can change.
export const spaceKindCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  key: z
    .string()
    .regex(
      /^[a-z][a-z0-9_]{0,62}$/,
      'Use lowercase letters, numbers and _, starting with a letter',
    ),
  name: name(100),
  sort_order: z.number().int().optional(),
});

export const spaceKindUpdateSchema = nonEmpty(
  z
    .strictObject({
      name: name(100),
      sort_order: z.number().int(),
      archived_at: archivedAt,
    })
    .partial(),
);

// Spaces. location_id is required on create and immutable afterwards.
export const spaceCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  location_id: z.uuid(),
  space_kind_id: z.uuid(),
  parent_space_id: z.uuid().nullable().optional(),
  name: name(200),
  description: optionalText(2000).optional(),
  capacity: z.number().int().min(0).nullable().optional(),
  sort_order: z.number().int().optional(),
});

export const spaceUpdateSchema = nonEmpty(
  z
    .strictObject({
      space_kind_id: z.uuid(),
      parent_space_id: z.uuid().nullable(),
      name: name(200),
      description: optionalText(2000),
      capacity: z.number().int().min(0).nullable(),
      sort_order: z.number().int(),
      archived_at: archivedAt,
    })
    .partial(),
);

// Weekly hours. One row per open interval; overnight hours are two rows
// (e.g. 20:00-24:00 and 00:00-02:00 on the next day's row).
const spaceHoursFields = {
  day_of_week: z.number().int().min(1, 'Day 1-7 (1 = Monday)').max(7, 'Day 1-7 (1 = Monday)'),
  opens_at: timeOfDay,
  closes_at: closingTime,
  effective_from: isoDate.nullable(),
  effective_to: isoDate.nullable(),
};

const spaceHoursRefine = (v: { opens_at?: string; closes_at?: string }) =>
  v.opens_at === undefined ||
  v.closes_at === undefined ||
  toSeconds(v.closes_at) > toSeconds(v.opens_at);

export const spaceHourCreateSchema = z
  .strictObject({
    organization_id: z.uuid(),
    location_id: z.uuid(),
    space_id: z.uuid(),
    ...spaceHoursFields,
    effective_from: isoDate.nullable().optional(),
    effective_to: isoDate.nullable().optional(),
  })
  .refine(
    (v) => toSeconds(v.closes_at) > toSeconds(v.opens_at),
    'Closing time must be after opening time',
  )
  .refine(dateRangeOk, 'End date must be on or after the start date');

export const spaceHourUpdateSchema = nonEmpty(
  z
    .strictObject(spaceHoursFields)
    .partial()
    .refine(spaceHoursRefine, 'Closing time must be after opening time')
    .refine(dateRangeOk, 'End date must be on or after the start date'),
);

// Closures: a space is closed, or with no space_id the whole location.
const closureRange = (v: { starts_at?: string; ends_at?: string }) =>
  v.starts_at === undefined ||
  v.ends_at === undefined ||
  Date.parse(v.ends_at) > Date.parse(v.starts_at);

const closureTimes = {
  starts_at: z.iso.datetime({ offset: true }),
  ends_at: z.iso.datetime({ offset: true }),
  reason: optionalText(500),
};

export const spaceClosureCreateSchema = z
  .strictObject({
    organization_id: z.uuid(),
    location_id: z.uuid(),
    space_id: z.uuid().nullable(),
    ...closureTimes,
  })
  .refine((v) => Date.parse(v.ends_at) > Date.parse(v.starts_at), 'End must be after start');

export const spaceClosureUpdateSchema = nonEmpty(
  z.strictObject(closureTimes).partial().refine(closureRange, 'End must be after start'),
);

export type SpaceKindCreate = z.infer<typeof spaceKindCreateSchema>;
export type SpaceKindUpdate = z.infer<typeof spaceKindUpdateSchema>;
export type SpaceCreate = z.infer<typeof spaceCreateSchema>;
export type SpaceUpdate = z.infer<typeof spaceUpdateSchema>;
export type SpaceHourCreate = z.infer<typeof spaceHourCreateSchema>;
export type SpaceHourUpdate = z.infer<typeof spaceHourUpdateSchema>;
export type SpaceClosureCreate = z.infer<typeof spaceClosureCreateSchema>;
export type SpaceClosureUpdate = z.infer<typeof spaceClosureUpdateSchema>;
