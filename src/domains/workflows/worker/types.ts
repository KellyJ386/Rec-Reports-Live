// Ports the workflow worker needs. Production implementations are in ./supabase-ports.ts and
// take a service-role client created in src/lib/cron; tests use src/lib/cron/testing.

export interface MatchedRule {
  ruleId: string;
  taskTemplateId: string;
}

/** Worker functions of migration 000300 (service_role only). */
export interface WorkflowPort {
  /** Enabled rules whose type, location and condition match the event. */
  matchRules(eventId: string): Promise<MatchedRule[]>;
  /** The task for (event, rule's template): created now, or the one made on an earlier run. Null: the rule no longer applies. */
  createTaskFromEvent(eventId: string, ruleId: string): Promise<string | null>;
  /** Emits task.overdue once per task per due date. Returns how many it emitted. */
  emitOverdueEvents(limit: number): Promise<number>;
}

/** The task fields a notification needs. Never the instructions. */
export interface TaskSnapshot {
  id: string;
  title: string;
  status: string;
  priority: string;
  assignedPersonId: string | null;
  assignedJobTitleId: string | null;
}

export interface TaskReader {
  getTask(taskId: string): Promise<TaskSnapshot | null>;
}

export interface TaskNotificationInput {
  eventId: string;
  personId: string;
  kind: string;
  title: string;
  body?: string | null;
  linkPath?: string | null;
  urgency?: 'normal' | 'high' | 'critical';
}

/**
 * What the task handlers need from the communications domain (its `create_notification` and
 * `task_recipient_person_ids` service functions). Structurally satisfied by that domain's port.
 */
export interface TaskNotifier {
  createNotification(input: TaskNotificationInput): Promise<string | null>;
  taskRecipientPersonIds(taskId: string): Promise<string[]>;
}
