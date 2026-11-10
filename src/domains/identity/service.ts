// Identity domain services: people, accounts, roles, role assignments, job titles and
// permission overrides. Reads and writes go through the caller's session client, so RLS
// (including the tier rule in docs/SECURITY.md) decides what is allowed.
import { createClient } from '@/lib/supabase/server';
import type { Tables } from '@/lib/supabase/database.types';
import { fail, failure, ok, requireChanged, type Result } from '@/lib/db-errors';
import { fetchAllRows, pageRange, toPaged, type Paged } from '@/lib/paging';
import { displayName, type PermissionLevel } from './logic';
import type {
  JobTitleCreate,
  JobTitleUpdate,
  PersonCreate,
  PersonJobTitleCreate,
  PersonUpdate,
  RoleAssignmentCreate,
  RoleCreate,
  RoleUpdate,
  UserPermissionCreate,
} from './schemas';

export type Person = Pick<
  Tables<'people'>,
  | 'id'
  | 'first_name'
  | 'last_name'
  | 'preferred_name'
  | 'email'
  | 'phone'
  | 'employee_number'
  | 'archived_at'
>;
export type Role = Pick<
  Tables<'roles'>,
  'id' | 'organization_id' | 'key' | 'name' | 'description' | 'rank' | 'archived_at'
>;
export type ModuleRow = Pick<Tables<'modules'>, 'key' | 'name' | 'sort_order'>;
export type JobTitle = Pick<Tables<'job_titles'>, 'id' | 'name' | 'archived_at'>;
export type PersonAssignment = {
  id: string;
  role_id: string;
  location_id: string | null;
  role: { key: string; name: string; rank: number } | null;
};
export type PersonJobTitleRow = {
  id: string;
  job_title_id: string;
  location_id: string | null;
  job_title: { name: string } | null;
};
export type UserPermissionRow = {
  id: string;
  module_key: string;
  location_id: string | null;
  level: PermissionLevel;
};
export type AccountStatus = 'active' | 'disabled' | 'none';

const PERSON_COLUMNS =
  'id, first_name, last_name, preferred_name, email, phone, employee_number, archived_at';
const ROLE_COLUMNS = 'id, organization_id, key, name, description, rank, archived_at';
const NUMBER_CONFLICT = 'Someone in this organization already has that employee number.';

// ---- people ----

export type PeopleQuery = {
  page: number;
  /** Search words from searchWords(): each must match a name, email or employee number. */
  words: string[];
  locationId?: string;
  status: 'active' | 'archived' | 'all';
};

function wordFilter(word: string): string {
  const w = `*${word}*`;
  return [
    `first_name.ilike.${w}`,
    `last_name.ilike.${w}`,
    `preferred_name.ilike.${w}`,
    `email.ilike.${w}`,
    `employee_number.ilike.${w}`,
  ].join(',');
}

/** One page of people. Filters (search, location, active/archived) run in the database. */
export async function listPeople(
  orgId: string,
  query: PeopleQuery,
): Promise<Result<Paged<Person>>> {
  const supabase = await createClient();
  const { from, to } = pageRange(query.page);

  let rows: Person[] | null;
  let total: number | null;
  if (query.locationId) {
    let q = supabase
      .from('people')
      .select(`${PERSON_COLUMNS}, role_assignments!inner(location_id)`, { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('role_assignments.location_id', query.locationId);
    if (query.status === 'active') q = q.is('archived_at', null);
    if (query.status === 'archived') q = q.not('archived_at', 'is', null);
    for (const w of query.words) q = q.or(wordFilter(w));
    const res = await q.order('last_name').order('first_name').order('id').range(from, to);
    if (res.error) return failure(res.error);
    rows = (res.data ?? []).map((r) => ({
      id: r.id,
      first_name: r.first_name,
      last_name: r.last_name,
      preferred_name: r.preferred_name,
      email: r.email,
      phone: r.phone,
      employee_number: r.employee_number,
      archived_at: r.archived_at,
    }));
    total = res.count;
  } else {
    let q = supabase
      .from('people')
      .select(PERSON_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId);
    if (query.status === 'active') q = q.is('archived_at', null);
    if (query.status === 'archived') q = q.not('archived_at', 'is', null);
    for (const w of query.words) q = q.or(wordFilter(w));
    const res = await q.order('last_name').order('first_name').order('id').range(from, to);
    if (res.error) return failure(res.error);
    rows = res.data;
    total = res.count;
  }
  return ok(toPaged(rows, total, query.page));
}

export async function getPerson(orgId: string, id: string): Promise<Result<Person | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('people')
    .select(PERSON_COLUMNS)
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

/** Display names for a short list of person ids (for example the actors on one audit page). */
export async function getPersonNames(
  orgId: string,
  ids: readonly string[],
): Promise<Result<Record<string, string>>> {
  const unique = [...new Set(ids)].slice(0, 100);
  if (unique.length === 0) return ok({});
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('people')
    .select('id, first_name, last_name, preferred_name')
    .eq('organization_id', orgId)
    .in('id', unique);
  if (error) return failure(error);
  return ok(Object.fromEntries((data ?? []).map((p) => [p.id, displayName(p)])));
}

/** Person and first role/location in one step, through the database function. */
export async function createPersonWithAssignment(
  input: Omit<PersonCreate, 'organization_id'> & {
    organization_id: string;
    role_id: string;
    location_id: string | null;
  },
): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('create_person_with_assignment', {
    p_organization_id: input.organization_id,
    p_first_name: input.first_name,
    p_last_name: input.last_name,
    p_role_id: input.role_id,
    p_location_id: input.location_id,
    p_preferred_name: input.preferred_name ?? null,
    p_email: input.email ?? null,
    p_phone: input.phone ?? null,
    p_employee_number: input.employee_number ?? null,
  });
  if (error) return failure(error, { unique: NUMBER_CONFLICT });
  if (!data) return fail('The person was not added.');
  return ok({ id: data });
}

export async function updatePerson(
  orgId: string,
  id: string,
  patch: PersonUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('people')
    .update(patch)
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error, { unique: NUMBER_CONFLICT });
  return requireChanged(data);
}

export function setPersonArchived(orgId: string, id: string, archived: boolean) {
  return updatePerson(orgId, id, { archived_at: archived ? new Date().toISOString() : null });
}

/** Whether the person has a login account. Only people admins can read accounts. */
export async function getAccountStatus(
  orgId: string,
  personId: string,
): Promise<Result<AccountStatus>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('accounts')
    .select('disabled_at')
    .eq('organization_id', orgId)
    .eq('person_id', personId)
    .maybeSingle();
  if (error) return failure(error);
  if (!data) return ok('none');
  return ok(data.disabled_at ? 'disabled' : 'active');
}

// ---- roles ----

/** System roles plus this organization's custom roles. */
export async function listRoles(
  orgId: string,
  options: { includeArchived?: boolean } = {},
): Promise<Result<Role[]>> {
  const supabase = await createClient();
  return fetchAllRows<Role>((from, to) => {
    const q = supabase
      .from('roles')
      .select(ROLE_COLUMNS)
      .or(`organization_id.is.null,organization_id.eq.${orgId}`);
    return (options.includeArchived ? q : q.is('archived_at', null))
      .order('rank', { ascending: false })
      .order('name')
      .order('id')
      .range(from, to);
  });
}

export async function getRole(orgId: string, id: string): Promise<Result<Role | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('roles')
    .select(ROLE_COLUMNS)
    .eq('id', id)
    .or(`organization_id.is.null,organization_id.eq.${orgId}`)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

export async function createRole(input: RoleCreate): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.from('roles').insert(input).select('id').single();
  if (error) return failure(error, { unique: 'A role with that name or key already exists.' });
  return ok({ id: data.id });
}

/** Only this organization's own custom roles can change; system roles are never matched. */
export async function updateRole(
  orgId: string,
  id: string,
  patch: RoleUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('roles')
    .update(patch)
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error, { unique: 'A role with that name or key already exists.' });
  return requireChanged(data);
}

export function setRoleArchived(orgId: string, id: string, archived: boolean) {
  return updateRole(orgId, id, { archived_at: archived ? new Date().toISOString() : null });
}

export async function listModules(): Promise<Result<ModuleRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<ModuleRow>((from, to) =>
    supabase
      .from('modules')
      .select('key, name, sort_order')
      .order('sort_order')
      .order('key')
      .range(from, to),
  );
}

/** Default levels per role, as roleId -> moduleKey -> level. */
export async function listRoleDefaults(
  roleIds: readonly string[],
): Promise<Result<Record<string, Record<string, PermissionLevel>>>> {
  const ids = [...new Set(roleIds)];
  if (ids.length === 0) return ok({});
  const supabase = await createClient();
  const rows = await fetchAllRows<{ role_id: string; module_key: string; level: PermissionLevel }>(
    (from, to) =>
      supabase
        .from('role_default_permissions')
        .select('role_id, module_key, level')
        .in('role_id', ids)
        .order('role_id')
        .order('module_key')
        .range(from, to),
  );
  if (!rows.ok) return rows;
  const out: Record<string, Record<string, PermissionLevel>> = {};
  for (const r of rows.data) (out[r.role_id] ??= {})[r.module_key] = r.level;
  return ok(out);
}

/** Sets one default level on a custom role: updates the row if there is one, else adds it. */
export async function setRoleDefault(
  orgId: string,
  roleId: string,
  moduleKey: string,
  level: PermissionLevel,
): Promise<Result<number>> {
  const supabase = await createClient();
  const role = await supabase
    .from('roles')
    .select('id')
    .eq('id', roleId)
    .eq('organization_id', orgId)
    .maybeSingle();
  if (role.error) return failure(role.error);
  if (!role.data) return fail('Only your own custom roles can be changed.');

  const existing = await supabase
    .from('role_default_permissions')
    .select('id')
    .eq('role_id', roleId)
    .eq('module_key', moduleKey)
    .maybeSingle();
  if (existing.error) return failure(existing.error);
  if (existing.data) {
    const { data, error } = await supabase
      .from('role_default_permissions')
      .update({ level })
      .eq('id', existing.data.id)
      .select('id');
    if (error) return failure(error);
    return requireChanged(data);
  }
  const { data, error } = await supabase
    .from('role_default_permissions')
    .insert({ role_id: roleId, module_key: moduleKey, level })
    .select('id');
  if (error) return failure(error);
  return requireChanged(data);
}

// ---- role assignments ----

export async function listRoleAssignments(
  orgId: string,
  personId: string,
): Promise<Result<PersonAssignment[]>> {
  const supabase = await createClient();
  const rows = await fetchAllRows((from, to) =>
    supabase
      .from('role_assignments')
      .select('id, role_id, location_id, roles(key, name, rank)')
      .eq('organization_id', orgId)
      .eq('person_id', personId)
      .order('created_at')
      .order('id')
      .range(from, to),
  );
  if (!rows.ok) return rows;
  return ok(
    rows.data.map((r) => ({
      id: r.id,
      role_id: r.role_id,
      location_id: r.location_id,
      role: r.roles ?? null,
    })),
  );
}

export async function addRoleAssignment(
  input: RoleAssignmentCreate,
): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('role_assignments')
    .insert(input)
    .select('id')
    .single();
  if (error) return failure(error, { unique: 'That person already has that role there.' });
  return ok({ id: data.id });
}

export async function removeRoleAssignment(orgId: string, id: string): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('role_assignments')
    .delete()
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error);
  return requireChanged(data);
}

// ---- job titles ----

export async function listJobTitles(
  orgId: string,
  options: { includeArchived?: boolean } = {},
): Promise<Result<JobTitle[]>> {
  const supabase = await createClient();
  return fetchAllRows<JobTitle>((from, to) => {
    const q = supabase
      .from('job_titles')
      .select('id, name, archived_at')
      .eq('organization_id', orgId);
    return (options.includeArchived ? q : q.is('archived_at', null))
      .order('name')
      .order('id')
      .range(from, to);
  });
}

export async function createJobTitle(input: JobTitleCreate): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.from('job_titles').insert(input).select('id').single();
  if (error) return failure(error, { unique: 'A job title with that name already exists.' });
  return ok({ id: data.id });
}

export async function updateJobTitle(
  orgId: string,
  id: string,
  patch: JobTitleUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('job_titles')
    .update(patch)
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error, { unique: 'A job title with that name already exists.' });
  return requireChanged(data);
}

export function setJobTitleArchived(orgId: string, id: string, archived: boolean) {
  return updateJobTitle(orgId, id, { archived_at: archived ? new Date().toISOString() : null });
}

export async function listPersonJobTitles(
  orgId: string,
  personId: string,
): Promise<Result<PersonJobTitleRow[]>> {
  const supabase = await createClient();
  const rows = await fetchAllRows((from, to) =>
    supabase
      .from('person_job_titles')
      .select('id, job_title_id, location_id, job_titles(name)')
      .eq('organization_id', orgId)
      .eq('person_id', personId)
      .order('created_at')
      .order('id')
      .range(from, to),
  );
  if (!rows.ok) return rows;
  return ok(
    rows.data.map((r) => ({
      id: r.id,
      job_title_id: r.job_title_id,
      location_id: r.location_id,
      job_title: r.job_titles ?? null,
    })),
  );
}

export async function addPersonJobTitle(
  input: PersonJobTitleCreate,
): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('person_job_titles')
    .insert(input)
    .select('id')
    .single();
  if (error) return failure(error, { unique: 'That person already has that job title there.' });
  return ok({ id: data.id });
}

export async function removePersonJobTitle(orgId: string, id: string): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('person_job_titles')
    .delete()
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error);
  return requireChanged(data);
}

// ---- permission overrides ----

export async function listUserPermissions(
  orgId: string,
  personId: string,
): Promise<Result<UserPermissionRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<UserPermissionRow>((from, to) =>
    supabase
      .from('user_permissions')
      .select('id, module_key, location_id, level')
      .eq('organization_id', orgId)
      .eq('person_id', personId)
      .order('module_key')
      .order('id')
      .range(from, to),
  );
}

/** Sets an override: changes the level if one exists for that module and scope, else adds it. */
export async function setUserPermission(input: UserPermissionCreate): Promise<Result<number>> {
  const supabase = await createClient();
  let find = supabase
    .from('user_permissions')
    .select('id')
    .eq('organization_id', input.organization_id)
    .eq('person_id', input.person_id)
    .eq('module_key', input.module_key);
  find =
    input.location_id === null
      ? find.is('location_id', null)
      : find.eq('location_id', input.location_id);
  const existing = await find.maybeSingle();
  if (existing.error) return failure(existing.error);

  if (existing.data) {
    const { data, error } = await supabase
      .from('user_permissions')
      .update({ level: input.level })
      .eq('id', existing.data.id)
      .select('id');
    if (error) return failure(error);
    return requireChanged(data);
  }
  const { data, error } = await supabase.from('user_permissions').insert(input).select('id');
  if (error) return failure(error);
  return requireChanged(data);
}

export async function removeUserPermission(orgId: string, id: string): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('user_permissions')
    .delete()
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error);
  return requireChanged(data);
}
