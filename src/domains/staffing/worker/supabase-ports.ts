import type { SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '@/lib/supabase/database.types';
import { PortError } from '@/lib/cron/error-class';
import type { ShiftSnapshot, StaffingPort } from './types';

/**
 * Supabase implementation of the staffing worker port. The client must be the service-role client
 * built in src/lib/cron/jobs.ts. Everything goes through the service_role worker functions; no
 * table is read directly.
 */
type Client = SupabaseClient<Database>;

export function createStaffingPort(client: Client): StaffingPort {
  return {
    async shiftForEvent(eventId): Promise<ShiftSnapshot | null> {
      const { data, error } = await client.rpc('worker_shift_for_event', { p_event_id: eventId });
      if (error) throw new PortError('worker_shift_for_event', error.code);
      const row = data?.[0];
      if (!row) return null;
      return {
        shiftId: row.shift_id,
        locationId: row.location_id,
        locationName: row.location_name,
        timezone: row.location_timezone,
        positionName: row.position_name,
        startsAt: row.starts_at,
        endsAt: row.ends_at,
        assignedPersonId: row.assigned_person_id,
        status: row.status,
      };
    },
    async recipients(eventId) {
      const { data, error } = await client.rpc('worker_shift_event_recipients', {
        p_event_id: eventId,
      });
      if (error) throw new PortError('worker_shift_event_recipients', error.code);
      return (data ?? []).map((r) => ({ personId: r.person_id, reason: r.reason }));
    },
    async emitUncovered(withinHours, limit) {
      const { data, error } = await client.rpc('emit_uncovered_shift_events', {
        p_within: `${withinHours} hours`,
        ...(limit === undefined ? {} : { p_limit: limit }),
      });
      if (error) throw new PortError('emit_uncovered_shift_events', error.code);
      return data ?? 0;
    },
  };
}
