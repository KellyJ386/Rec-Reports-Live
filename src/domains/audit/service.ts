// Audit domain services. audit_log is append-only and written by database triggers; this
// domain only reads it. RLS decides which rows the caller sees (audit_log >= view).
import { createClient } from '@/lib/supabase/server';
import type { Tables } from '@/lib/supabase/database.types';
import { failure, ok, type Result } from '@/lib/db-errors';
import { pageRange, toPaged, type Paged } from '@/lib/paging';
import type { AuditLogFilter } from './schemas';

export type AuditEntry = Pick<
  Tables<'audit_log'>,
  | 'id'
  | 'occurred_at'
  | 'location_id'
  | 'actor_person_id'
  | 'actor_role'
  | 'action'
  | 'table_name'
  | 'row_id'
  | 'changed_columns'
>;

/**
 * One page of audit entries, newest first. Old and new row contents are not selected: the
 * list shows what changed (table, action, column names), not the values.
 */
export async function listAuditLog(
  filter: Omit<AuditLogFilter, 'limit'>,
  page: number,
): Promise<Result<Paged<AuditEntry>>> {
  const supabase = await createClient();
  const { from, to } = pageRange(page);
  let q = supabase
    .from('audit_log')
    .select(
      'id, occurred_at, location_id, actor_person_id, actor_role, action, table_name, row_id, changed_columns',
      { count: 'exact' },
    )
    .eq('organization_id', filter.organization_id);
  if (filter.location_id) q = q.eq('location_id', filter.location_id);
  if (filter.table_name) q = q.eq('table_name', filter.table_name);
  if (filter.action) q = q.eq('action', filter.action);
  if (filter.since) q = q.gte('occurred_at', filter.since);
  if (filter.until) q = q.lt('occurred_at', filter.until);
  const { data, count, error } = await q
    .order('occurred_at', { ascending: false })
    .order('id', { ascending: false })
    .range(from, to);
  if (error) return failure(error);
  return ok(toPaged(data, count, page));
}
