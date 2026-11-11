import { chunk, clip, isUuid, runAll } from '@/lib/cron/run-all';
import type { EventHandler, HandlerContext, OutboxEvent } from '@/lib/cron/outbox-types';
import type { TaskNotifier, TaskReader, WorkflowPort } from './types';

/**
 * Ledger names. They are stored in outbox_event_handlers, so renaming one makes a retried event
 * run that step again: add a new name, do not rename.
 */
export const HANDLER_NAMES = {
  workflowRules: 'workflow_rules',
  notifyTaskRecipients: 'notify_task_recipients',
  notifyTaskOverdue: 'notify_task_overdue',
} as const;

/** App-relative link to a task (screens: src/app/app/tasks). Must match the DB link_path rule. */
export function taskLink(taskId: string): string {
  return `/app/tasks/${taskId}`;
}

const CLOSED = new Set(['done', 'cancelled']);
/** People per create_notifications call. The database takes 10,000; small chunks keep each call short. */
export const NOTIFY_CHUNK = 200;

/**
 * Workflow rules -> tasks. For every rule that matches the event, create the task through
 * create_task_from_event, which is idempotent on (event, template): a re-run returns the task
 * made the first time. Used for every event type a rule may listen to.
 */
export function createRulesHandler(workflows: WorkflowPort): EventHandler {
  return {
    name: HANDLER_NAMES.workflowRules,
    async run(event: OutboxEvent, ctx: HandlerContext) {
      const matches = await workflows.matchRules(event.id);
      const ruleIds = [...new Set(matches.map((m) => m.ruleId))];
      await runAll(ruleIds, async (ruleId) => {
        await ctx.checkpoint();
        await workflows.createTaskFromEvent(event.id, ruleId);
      });
    },
  };
}

function actorOf(event: OutboxEvent): string | null {
  const actor = event.payload.actor_person_id;
  return isUuid(actor) ? actor : null;
}

/**
 * task.created / task.assigned -> tell whoever the task is for. The task is re-read through the
 * event (worker_task_for_event; the payload is only a hint) and nothing is sent for a task that
 * is already finished. The person who made the change is not told about their own action.
 * Recipients get their notification in chunks, one `create_notifications` call each.
 */
export function createTaskNotifyHandler(
  deps: { tasks: TaskReader; notifier: TaskNotifier },
  kind: 'task_created' | 'task_assigned',
): EventHandler {
  return {
    name: HANDLER_NAMES.notifyTaskRecipients,
    async run(event: OutboxEvent, ctx: HandlerContext) {
      const task = await deps.tasks.getTaskForEvent(event.id);
      if (!task || CLOSED.has(task.status)) return;
      const actor = actorOf(event);
      const recipients = (await deps.notifier.taskRecipientPersonIds(task.id)).filter(
        (id) => id !== actor,
      );
      const urgent = task.priority === 'urgent' || task.priority === 'high';
      for (const personIds of chunk(recipients, NOTIFY_CHUNK)) {
        await ctx.checkpoint();
        await deps.notifier.createNotifications({
          eventId: event.id,
          personIds,
          kind,
          title: clip(
            kind === 'task_created' ? `New task: ${task.title}` : `Assigned to you: ${task.title}`,
            120,
          ),
          body: null,
          linkPath: taskLink(task.id),
          urgency: urgent ? 'high' : 'normal',
        });
      }
    },
  };
}

/**
 * task.overdue -> tell the people the task is for AND the managers. Recipients are the union of
 * `escalate_overdue_task` (the managers at the task's location; it also records the escalation,
 * once per event) and `task_recipient_person_ids` (the current assignee, or the active holders of
 * the job title it is routed to). Everyone gets the same notification kind for the same event, so
 * a manager who is also the assignee gets one notice, and the text is neutral: it says the task
 * is overdue and nothing about who is to blame. A re-run gets the same people and
 * `create_notifications` skips the ones already told. Further escalation is for workflow rules:
 * `task.overdue` is a rule trigger, so a manager can add a rule that creates a follow-up task.
 */
export function createOverdueNotifyHandler(deps: {
  tasks: TaskReader;
  workflows: WorkflowPort;
  notifier: TaskNotifier;
}): EventHandler {
  return {
    name: HANDLER_NAMES.notifyTaskOverdue,
    async run(event: OutboxEvent, ctx: HandlerContext) {
      const escalated = await deps.workflows.escalateOverdue(event.id);
      const task = await deps.tasks.getTaskForEvent(event.id);
      if (!task || CLOSED.has(task.status)) return;
      const assigned = await deps.notifier.taskRecipientPersonIds(task.id);
      const recipients = [...new Set([...escalated, ...assigned])];
      for (const personIds of chunk(recipients, NOTIFY_CHUNK)) {
        await ctx.checkpoint();
        await deps.notifier.createNotifications({
          eventId: event.id,
          personIds,
          kind: 'task_overdue',
          title: clip(`Task overdue: ${task.title}`, 120),
          body: null,
          linkPath: taskLink(task.id),
          urgency: 'high',
        });
      }
    },
  };
}
