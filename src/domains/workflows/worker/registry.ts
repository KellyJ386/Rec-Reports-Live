import type { EventHandler, HandlerRegistry } from '@/lib/cron/outbox-types';
import {
  createOverdueNotifyHandler,
  createRulesHandler,
  createTaskNotifyHandler,
} from './handlers';
import type { TaskNotifier, TaskReader, WorkflowPort } from './types';

/** Pilot event types that workflow rules may listen to (mirrors private.workflow_trigger_types()). */
export const RULE_EVENT_TYPES = [
  'booking.confirmed',
  'booking.rescheduled',
  'booking.cancelled',
  'shift.uncovered',
  'checklist.item_failed',
  'checklist.completed',
  'incident.submitted',
  'incident.reviewed',
  'task.overdue',
  'notice.published',
] as const;

export interface RegistryDeps {
  workflows: WorkflowPort;
  tasks: TaskReader;
  notifier: TaskNotifier;
  /** Handlers owned by other domains, appended after the built-in ones for their type, in order. */
  external?: readonly { type: string; handler: EventHandler }[];
}

/**
 * Event type -> ordered, named handlers. Rules run first, so a rule-made task exists before the
 * notifications for the same event. A type missing from the registry completes without action.
 *
 *   booking.* shift.* checklist.* incident.*  workflow_rules
 *   task.created                              notify_task_recipients
 *   task.assigned                             notify_task_recipients
 *   task.overdue                              workflow_rules, notify_task_overdue
 *   notice.published                          workflow_rules, + communications handlers
 *   message.sent                              communications handlers
 */
export function buildHandlerRegistry(deps: RegistryDeps): HandlerRegistry {
  const registry = new Map<string, EventHandler[]>();
  const add = (type: string, handler: EventHandler) => {
    const list = registry.get(type) ?? [];
    if (list.some((h) => h.name === handler.name)) {
      throw new Error(`duplicate handler ${handler.name} for ${type}`);
    }
    registry.set(type, [...list, handler]);
  };

  const rules = createRulesHandler(deps.workflows);
  for (const type of RULE_EVENT_TYPES) add(type, rules);

  add('task.created', createTaskNotifyHandler(deps, 'task_created'));
  add('task.assigned', createTaskNotifyHandler(deps, 'task_assigned'));
  add('task.overdue', createOverdueNotifyHandler(deps));

  for (const { type, handler } of deps.external ?? []) add(type, handler);
  return registry;
}
