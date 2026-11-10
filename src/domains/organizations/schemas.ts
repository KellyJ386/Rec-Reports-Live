// Input validation for the organizations domain. Server-side only (docs/SECURITY.md:
// every mutation is validated on the server). Mirrors the database checks in
// supabase/migrations/20261111000100_organizations_and_resources.sql.
//
// Only fields a tenant user may supply are listed. id, organization_id (on update),
// created_at and updated_at are never accepted: the schemas are strict, so an
// unknown key such as organization_id on an update is rejected, not ignored.
import { z } from 'zod';

const SUPPORTED_TIME_ZONES = new Set<string>(Intl.supportedValuesOf('timeZone'));

// Mirrors private.tg_validate_timezone: 'UTC' or an Area/Location name the
// IANA database knows. Rejects 'EST', 'UTC+5' and other slash-less names.
const timeZone = z
  .string()
  .trim()
  .refine(
    (tz) => tz === 'UTC' || (tz.includes('/') && SUPPORTED_TIME_ZONES.has(tz)),
    'Pick a valid time zone such as America/New_York',
  );

const name = (max: number) => z.string().trim().min(1, 'Enter a name').max(max);

const optionalText = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .transform((v) => (v === '' ? null : v))
    .nullable();

const archivedAt = z.iso.datetime({ offset: true }).nullable();

export const organizationUpdateSchema = z
  .strictObject({
    name: name(200),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, 'Nothing to update');

export const organizationSettingsUpdateSchema = z
  .strictObject({
    default_timezone: timeZone,
    week_starts_on: z.number().int().min(0).max(6), // 0 = Sunday
    settings: z.record(z.string(), z.unknown()),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, 'Nothing to update');

// Insert needs an existing organization; the organization row itself is created
// by service_role only, so there is no organization create schema.
export const locationCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  name: name(200),
  code: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9_-]{1,20}$/, 'Use 1-20 letters, numbers, - or _')
    .nullable()
    .optional(),
  timezone: timeZone,
  address: optionalText(500).optional(),
  phone: optionalText(40).optional(),
});

export const locationUpdateSchema = z
  .strictObject({
    name: name(200),
    code: z
      .string()
      .trim()
      .regex(/^[A-Za-z0-9_-]{1,20}$/, 'Use 1-20 letters, numbers, - or _')
      .nullable(),
    timezone: timeZone,
    address: optionalText(500),
    phone: optionalText(40),
    archived_at: archivedAt,
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, 'Nothing to update');

export type OrganizationUpdate = z.infer<typeof organizationUpdateSchema>;
export type OrganizationSettingsUpdate = z.infer<typeof organizationSettingsUpdateSchema>;
export type LocationCreate = z.infer<typeof locationCreateSchema>;
export type LocationUpdate = z.infer<typeof locationUpdateSchema>;
