import { clip, isUuid, runAll } from '@/lib/cron/run-all';
import type { EventHandler, OutboxEvent } from '@/lib/cron/outbox-types';
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

/**
 * Workflow rules -> tasks. For every rule that matches the event, create the task through
 * create_task_from_event, which is idempotent on (event, template): a re-run returns the task
 * made the first time. Used for every event type a rule may listen to.
 */
export function createRulesHandler(workflows: WorkflowPort): EventHandler {
  return {
    name: HANDLER_NAMES.workflowRules,
    async run(event: OutboxEvent) {
      const matches = await workflows.matchRules(event.id);
      const ruleIds = [...new Set(matches.map((m) => m.ruleId))];
      await runAll(ruleIds, async (ruleId) => {
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
 * task.created / task.assigned -> tell whoever the task is for. The task is re-read by id (the
 * payload is only a hint) and nothing is sent for a task that is already finished. The person who
 * made the change is not told about their own action.
 */
export function createTaskNotifyHandler(
  deps: { tasks: TaskReader; notifier: TaskNotifier },
  kind: 'task_created' | 'task_assigned',
): EventHandler {
  return {
    name: HANDLER_NAMES.notifyTaskRecipients,
    async run(event: OutboxEvent) {
      const task = await deps.tasks.getTask(event.entityId);
      if (!task || CLOSED.has(task.status)) return;
      const actor = actorOf(event);
      const recipients = (await deps.notifier.taskRecipientPersonIds(task.id)).filter(
        (id) => id !== actor,
      );
      const urgent = task.priority === 'urgent' || task.priority === 'high';
      await runAll(recipients, async (personId) => {
        await deps.notifier.createNotification({
          eventId: event.id,
          personId,
          kind,
          title: clip(
            kind === 'task_created' ? `New task: ${task.title}` : `Assigned to you: ${task.title}`,
            120,
          ),
          body: null,
          linkPath: taskLink(task.id),
          urgency: urgent ? 'high' : 'normal',
        });
      });
    },
  };
}

/**
 * task.overdue -> tell the people the task is for, at "high" urgency. Escalation beyond that is
 * done by workflow rules: `task.overdue` is a rule trigger, so a manager can add a rule that
 * creates an escalation task (the generic rules handler runs first for this event type). The
 * database gives workers no function to reassign a task or write an `escalated` history row, so
 * the worker does neither. An unassigned task has no recipients and notifies nobody.
 */
export function createOverdueNotifyHandler(deps: {
  tasks: TaskReader;
  notifier: TaskNotifier;
}): EventHandler {
  return {
    name: HANDLER_NAMES.notifyTaskOverdue,
    async run(event: OutboxEvent) {
      const task = await deps.tasks.getTask(event.entityId);
      if (!task || CLOSED.has(task.status)) return;
      const recipients = await deps.notifier.taskRecipientPersonIds(task.id);
      await runAll(recipients, async (personId) => {
        await deps.notifier.createNotification({
          eventId: event.id,
          personId,
          kind: 'task_overdue',
          title: clip(`Overdue: ${task.title}`, 120),
          body: 'This task is past its due time.',
          linkPath: taskLink(task.id),
          urgency: 'high',
        });
      });
    },
  };
}
