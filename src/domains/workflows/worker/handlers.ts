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
 * task.overdue -> tell the people `escalate_overdue_task` names (the managers at the task's
 * location), at "high" urgency. The database decides: it returns nobody when the assignee has
 * already acted or the task is closed, and it records the escalation once per event, so a re-run
 * gets the same people and `create_notifications` skips the ones already told. Further escalation
 * is for workflow rules: `task.overdue` is a rule trigger, so a manager can add a rule that
 * creates a follow-up task (the generic rules handler runs first for this event type).
 */
export function createOverdueNotifyHandler(deps: {
  tasks: TaskReader;
  workflows: WorkflowPort;
  notifier: TaskNotifier;
}): EventHandler {
  return {
    name: HANDLER_NAMES.notifyTaskOverdue,
    async run(event: OutboxEvent, ctx: HandlerContext) {
      const recipients = await deps.workflows.escalateOverdue(event.id);
      if (recipients.length === 0) return;
      const task = await deps.tasks.getTaskForEvent(event.id);
      if (!task || CLOSED.has(task.status)) return;
      for (const personIds of chunk(recipients, NOTIFY_CHUNK)) {
        await ctx.checkpoint();
        await deps.notifier.createNotifications({
          eventId: event.id,
          personIds,
          kind: 'task_overdue',
          title: clip(`Overdue: ${task.title}`, 120),
          body: task.assignedPersonId
            ? 'The person it is assigned to has not started it.'
            : 'Nobody has picked this task up.',
          linkPath: taskLink(task.id),
          urgency: 'high',
        });
      }
    },
  };
}
