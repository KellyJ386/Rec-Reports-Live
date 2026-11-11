import type { SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '@/lib/supabase/database.types';
import { PortError } from '@/lib/cron/error-class';
import type { OutboxEvent, OutboxPort } from '@/lib/cron/outbox-types';
import type { MatchedRule, TaskReader, TaskSnapshot, WorkflowPort } from './types';

/**
 * Supabase implementations of the workflow worker ports. The client must be the service-role
 * client built in src/lib/cron/jobs.ts (the only importer of the admin client). Everything here
 * calls the service_role worker functions (`worker_task_for_event` for the task a handler needs);
 * it reads no table directly.
 */
type Client = SupabaseClient<Database>;
type EventRow = Database['public']['Tables']['outbox_events']['Row'];

function toEvent(row: EventRow): OutboxEvent {
  const payload =
    typeof row.payload === 'object' && row.payload !== null && !Array.isArray(row.payload)
      ? (row.payload as Record<string, unknown>)
      : {};
  return {
    id: row.id,
    organizationId: row.organization_id,
    locationId: row.location_id,
    type: row.type,
    schemaVersion: row.schema_version,
    entityTable: row.entity_table,
    entityId: row.entity_id,
    payload,
    correlationId: row.correlation_id,
    attempts: row.attempts,
  };
}

export function createOutboxPort(client: Client): OutboxPort {
  return {
    async claim(worker, limit, lockSeconds) {
      const { data, error } = await client.rpc('claim_outbox_events', {
        p_worker: worker,
        p_limit: limit,
        p_lock_seconds: lockSeconds,
      });
      if (error) throw new PortError('claim_outbox_events', error.code);
      return (data ?? []).map(toEvent);
    },
    async complete(eventId, worker) {
      const { data, error } = await client.rpc('complete_outbox_event', {
        p_id: eventId,
        p_worker: worker,
      });
      if (error) throw new PortError('complete_outbox_event', error.code);
      return data === true;
    },
    async fail(eventId, worker, message) {
      const { data, error } = await client.rpc('fail_outbox_event', {
        p_id: eventId,
        p_worker: worker,
        p_error: message,
      });
      if (error) throw new PortError('fail_outbox_event', error.code);
      return data === 'pending' || data === 'dead' ? data : null;
    },
    async handlersDone(eventId) {
      const { data, error } = await client.rpc('outbox_handlers_done', { p_event_id: eventId });
      if (error) throw new PortError('outbox_handlers_done', error.code);
      return data ?? [];
    },
    async release(eventId, worker) {
      const { data, error } = await client.rpc('release_outbox_event', {
        p_id: eventId,
        p_worker: worker,
      });
      if (error) throw new PortError('release_outbox_event', error.code);
      return data === true;
    },
    async extendLock(eventId, worker, seconds) {
      const { data, error } = await client.rpc('extend_outbox_lock', {
        p_id: eventId,
        p_worker: worker,
        p_seconds: seconds,
      });
      if (error) throw new PortError('extend_outbox_lock', error.code);
      return data === true;
    },
    async recordHandler(eventId, handler) {
      const { data, error } = await client.rpc('record_outbox_handler', {
        p_event_id: eventId,
        p_handler: handler,
      });
      if (error) throw new PortError('record_outbox_handler', error.code);
      return data === true;
    },
  };
}

export function createWorkflowPort(client: Client): WorkflowPort {
  return {
    async matchRules(eventId): Promise<MatchedRule[]> {
      const { data, error } = await client.rpc('match_workflow_rules', { p_event_id: eventId });
      if (error) throw new PortError('match_workflow_rules', error.code);
      return (data ?? []).map((r) => ({ ruleId: r.rule_id, taskTemplateId: r.task_template_id }));
    },
    async createTaskFromEvent(eventId, ruleId) {
      const { data, error } = await client.rpc('create_task_from_event', {
        p_event_id: eventId,
        p_rule_id: ruleId,
      });
      if (error) throw new PortError('create_task_from_event', error.code);
      return data ?? null;
    },
    async emitOverdueEvents(limit) {
      const { data, error } = await client.rpc('emit_overdue_task_events', { p_limit: limit });
      if (error) throw new PortError('emit_overdue_task_events', error.code);
      return data ?? 0;
    },
    async escalateOverdue(eventId) {
      const { data, error } = await client.rpc('escalate_overdue_task', { p_event_id: eventId });
      if (error) throw new PortError('escalate_overdue_task', error.code);
      return data ?? [];
    },
  };
}

export function createTaskReader(client: Client): TaskReader {
  return {
    async getTaskForEvent(eventId): Promise<TaskSnapshot | null> {
      const { data, error } = await client.rpc('worker_task_for_event', { p_event_id: eventId });
      if (error) throw new PortError('worker_task_for_event', error.code);
      const row = data?.[0];
      if (!row) return null;
      return {
        id: row.task_id,
        title: row.title,
        status: row.status,
        priority: row.priority,
        dueAt: row.due_at,
        locationName: row.location_name,
        assignedPersonId: row.assigned_person_id,
        assignedJobTitleId: row.assigned_job_title_id,
      };
    },
  };
}
