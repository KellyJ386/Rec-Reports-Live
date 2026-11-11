// Input validation for the identity domain: people, accounts, roles, role
// assignments, permission overrides and job titles. Mirrors
// supabase/migrations/20261111000200_identity_and_access.sql and the tier rules
// in 20261111000300_rls_helpers_and_policies.sql (those are enforced by RLS;
// these schemas check one input's shape and the rules that do not need the database).
//
// Strict objects: id, organization_id (on update), created_at and updated_at are rejected.
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

export const permissionLevelSchema = z.enum(['none', 'view', 'edit', 'admin']);

// The 22 module keys seeded in the modules table (FK target of role defaults and overrides).
export const MODULE_KEYS = [
  'locations_spaces',
  'people_roles',
  'audit_log',
  'communications',
  'tasks',
  'staff_schedule',
  'availability_time_off',
  'shift_swaps',
  'time_clock',
  'timesheets',
  'certifications',
  'forms',
  'checklists',
  'incidents',
  'accidents',
  'daily_log',
  'headcounts',
  'facility_schedule',
  'equipment',
  'maintenance',
  'documents',
  'reports',
] as const;
export const moduleKeySchema = z.enum(MODULE_KEYS);

// Keys a custom role may never use: system roles, and the retired keys the constraint rejects.
const SYSTEM_ROLE_KEYS = ['super_admin', 'admin', 'manager', 'staff'];
const RETIRED_ROLE_KEYS = ['org_admin', 'facility_manager', 'gm', 'supervisor'];

// Custom roles only. System roles are seeded by migration and never created by tenants.
// Rank 1-79 keeps custom roles strictly below admin (80).
export const roleCreateSchema = z
  .strictObject({
    organization_id: z.uuid(),
    key: z
      .string()
      .regex(
        /^[a-z][a-z0-9_]{1,62}$/,
        'Use 2-63 lowercase letters, numbers or _, starting with a letter',
      ),
    name: name(100),
    description: optionalText(1000).optional(),
    rank: z.number().int().min(1, 'Rank must be 1-79').max(79, 'Rank must be 1-79'),
  })
  .refine((v) => !RETIRED_ROLE_KEYS.includes(v.key), {
    message: 'That key is retired. Choose another (supervisor is a job title, not a role)',
    path: ['key'],
  })
  .refine((v) => !SYSTEM_ROLE_KEYS.includes(v.key), {
    message: 'That key belongs to a built-in role',
    path: ['key'],
  });

// key is immutable and rank changes are allowed.
export const roleUpdateSchema = nonEmpty(
  z
    .strictObject({
      name: name(100),
      description: optionalText(1000),
      rank: z.number().int().min(1, 'Rank must be 1-79').max(79, 'Rank must be 1-79'),
      archived_at: archivedAt,
    })
    .partial(),
);

// Defaults for a custom role. organization_id is derived from the role by trigger.
export const roleDefaultPermissionCreateSchema = z.strictObject({
  role_id: z.uuid(),
  module_key: moduleKeySchema,
  level: permissionLevelSchema,
});

export const roleDefaultPermissionUpdateSchema = z.strictObject({
  level: permissionLevelSchema,
});

// People. A person can exist without an account.
const EMAIL = /^[^@\s]+@[^@\s]+$/;
const personFields = {
  first_name: name(100),
  last_name: name(100),
  preferred_name: optionalText(100),
  email: z.string().trim().max(320).regex(EMAIL, 'Enter an email address').nullable(),
  phone: optionalText(40),
  employee_number: optionalText(50),
};

export const personCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  ...personFields,
  preferred_name: personFields.preferred_name.optional(),
  email: personFields.email.optional(),
  phone: personFields.phone.optional(),
  employee_number: personFields.employee_number.optional(),
});

export const personUpdateSchema = nonEmpty(
  z.strictObject({ ...personFields, archived_at: archivedAt }).partial(),
);

// accounts: created by service_role (invite flow). Tenants may only set disabled_at.
export const accountUpdateSchema = z.strictObject({
  disabled_at: z.iso.datetime({ offset: true }).nullable(),
});

// Role assignments are created and deleted, never updated. location_id null = organization
// scope. Only the admin role may be organization scoped, and the role's rank and archived
// state need the role row, so the database trigger (tg_role_assignments_validate) and the
// RLS tier rule make that decision. The server action must check the role first.
export const roleAssignmentCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  person_id: z.uuid(),
  role_id: z.uuid(),
  location_id: z.uuid().nullable(),
});

// Overrides: a row grants nothing on its own. Only level is updatable.
export const userPermissionCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  person_id: z.uuid(),
  location_id: z.uuid().nullable(),
  module_key: moduleKeySchema,
  level: permissionLevelSchema,
});

export const userPermissionUpdateSchema = z.strictObject({
  level: permissionLevelSchema,
});

// Job titles route tasks and messages. They grant no permissions.
export const jobTitleCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  name: name(100),
});

export const jobTitleUpdateSchema = nonEmpty(
  z.strictObject({ name: name(100), archived_at: archivedAt }).partial(),
);

export const personJobTitleCreateSchema = z.strictObject({
  organization_id: z.uuid(),
  person_id: z.uuid(),
  job_title_id: z.uuid(),
  location_id: z.uuid().nullable(),
});

export type RoleCreate = z.infer<typeof roleCreateSchema>;
export type RoleUpdate = z.infer<typeof roleUpdateSchema>;
export type RoleDefaultPermissionCreate = z.infer<typeof roleDefaultPermissionCreateSchema>;
export type RoleDefaultPermissionUpdate = z.infer<typeof roleDefaultPermissionUpdateSchema>;
export type PersonCreate = z.infer<typeof personCreateSchema>;
export type PersonUpdate = z.infer<typeof personUpdateSchema>;
export type AccountUpdate = z.infer<typeof accountUpdateSchema>;
export type RoleAssignmentCreate = z.infer<typeof roleAssignmentCreateSchema>;
export type UserPermissionCreate = z.infer<typeof userPermissionCreateSchema>;
export type UserPermissionUpdate = z.infer<typeof userPermissionUpdateSchema>;
export type JobTitleCreate = z.infer<typeof jobTitleCreateSchema>;
export type JobTitleUpdate = z.infer<typeof jobTitleUpdateSchema>;
export type PersonJobTitleCreate = z.infer<typeof personJobTitleCreateSchema>;
