// Pure logic for the audit viewer: reading filters from the URL, plain labels.
import { addDays, zonedLocalToUtc } from '@/lib/time';
import { firstParam, parsePage } from '@/lib/paging';
import { auditLogFilterSchema, type AuditLogFilter } from './schemas';

/** Tables the audit trigger is attached to in Phase 1, with plain labels. */
export const AUDIT_TABLES: ReadonlyArray<{ name: string; label: string }> = [
  { name: 'locations', label: 'Locations' },
  { name: 'spaces', label: 'Spaces' },
  { name: 'space_kinds', label: 'Space kinds' },
  { name: 'space_hours', label: 'Space hours' },
  { name: 'space_closures', label: 'Closures' },
  { name: 'people', label: 'People' },
  { name: 'accounts', label: 'Login accounts' },
  { name: 'role_assignments', label: 'Role assignments' },
  { name: 'user_permissions', label: 'Permission overrides' },
  { name: 'roles', label: 'Roles' },
  { name: 'role_default_permissions', label: 'Role default permissions' },
  { name: 'job_titles', label: 'Job titles' },
  { name: 'person_job_titles', label: 'Person job titles' },
  { name: 'organizations', label: 'Organization' },
  { name: 'organization_settings', label: 'Organization settings' },
];

export function tableLabel(name: string): string {
  return AUDIT_TABLES.find((t) => t.name === name)?.label ?? name;
}

export const AUDIT_ACTIONS: ReadonlyArray<{
  value: 'insert' | 'update' | 'delete';
  label: string;
}> = [
  { value: 'insert', label: 'Added' },
  { value: 'update', label: 'Changed' },
  { value: 'delete', label: 'Removed' },
];

export function actionLabel(action: string): string {
  return AUDIT_ACTIONS.find((a) => a.value === action)?.label ?? action;
}

export type AuditFormValues = {
  table: string;
  action: string;
  from: string;
  to: string;
  location: string;
};

export type ParsedAuditQuery = {
  page: number;
  values: AuditFormValues;
  /** null when a filter was not valid; `problem` says which. */
  filter: Omit<AuditLogFilter, 'limit'> | null;
  problem: string | null;
};

const DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Reads the audit filters from search params. The date range is read in the organization's
 * time zone: "from" is the start of that day, "to" includes the whole of that day.
 */
export function parseAuditQuery(
  params: Record<string, string | string[] | undefined>,
  organizationId: string,
  timeZone: string,
): ParsedAuditQuery {
  const values: AuditFormValues = {
    table: firstParam(params.table) ?? '',
    action: firstParam(params.action) ?? '',
    from: firstParam(params.from) ?? '',
    to: firstParam(params.to) ?? '',
    location: firstParam(params.location) ?? '',
  };
  const page = parsePage(params.page);

  const since = DATE.test(values.from) ? zonedLocalToUtc(`${values.from}T00:00`, timeZone) : null;
  const nextDay = DATE.test(values.to) ? addDays(values.to, 1) : null;
  const until = nextDay ? zonedLocalToUtc(`${nextDay}T00:00`, timeZone) : null;
  if ((values.from && !since) || (values.to && !until)) {
    return { page, values, filter: null, problem: 'Enter dates as year-month-day.' };
  }

  const candidate = {
    organization_id: organizationId,
    ...(values.location ? { location_id: values.location } : {}),
    ...(values.table ? { table_name: values.table } : {}),
    ...(values.action ? { action: values.action } : {}),
    ...(since ? { since } : {}),
    ...(until ? { until } : {}),
  };
  const parsed = auditLogFilterSchema.safeParse(candidate);
  if (!parsed.success) {
    const message = parsed.error.issues[0]?.message ?? 'Check the filters.';
    return {
      page,
      values,
      filter: null,
      problem:
        message === 'until must be after since'
          ? 'The end date is before the start date.'
          : 'Check the filters and try again.',
    };
  }
  const { organization_id, location_id, table_name, action, since: from, until: to } = parsed.data;
  return {
    page,
    values,
    filter: { organization_id, location_id, table_name, action, since: from, until: to },
    problem: null,
  };
}
