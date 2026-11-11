// An in-memory stand-in for the database side of the worker, for tests only (nothing imports it
// in production). It implements every port the worker uses and enforces the SAME idempotency
// keys as the schema, so a handler that is not idempotent fails here the way it would there:
//
//   outbox_event_handlers   primary key (event_id, handler)
//   tasks                   unique (source_event_id, task_template_id)
//   notifications           unique (source_event_id, person_id, kind)
//   notification_deliveries unique (notification_id, channel)
//
// Claims count attempts, lock for a while, can be reclaimed after the lock expires, and only the
// worker holding a claim can complete or fail it. Time comes from `clock` so tests can move it.
import type { OutboxEvent, OutboxPort } from '@/lib/cron/outbox-types';
import type {
  MatchedRule,
  TaskNotificationInput,
  TaskReader,
  TaskSnapshot,
  WorkflowPort,
} from '@/domains/workflows';
import type {
  Channel,
  CreateNotificationInput,
  Delivery,
  DeliveryPort,
  NoticeReader,
  NoticeSnapshot,
  NotificationContent,
  NotificationPort,
  PushTarget,
  Urgency,
} from '@/domains/communications';

export const MAX_OUTBOX_ATTEMPTS = 8;
export const MAX_DELIVERY_ATTEMPTS = 5;

interface StoredEvent extends OutboxEvent {
  status: 'pending' | 'processing' | 'done' | 'dead';
  nextAttemptAt: number;
  lockedBy: string | null;
  lockExpiresAt: number | null;
  lastError: string | null;
}

export interface StoredNotification {
  id: string;
  personId: string;
  kind: string;
  title: string;
  body: string | null;
  linkPath: string | null;
  urgency: Urgency;
  sourceEventId: string;
}

export interface StoredDelivery {
  id: string;
  notificationId: string;
  personId: string;
  channel: Channel;
  status: 'pending' | 'sent' | 'failed' | 'skipped';
  attempts: number;
  nextAttemptAt: number;
  lockedBy: string | null;
  lockExpiresAt: number | null;
  lastError: string | null;
  providerMessageId: string | null;
}

export interface StoredTask extends TaskSnapshot {
  sourceEventId: string;
  templateId: string;
}

export interface StoredRule {
  id: string;
  templateId: string;
  eventType: string;
  enabled: boolean;
  /** Return false to say the condition does not match. */
  matches?: (event: OutboxEvent) => boolean;
}

const MINUTE = 60_000;

let counter = 0;
export function fakeId(): string {
  counter += 1;
  const hex = counter.toString(16).padStart(12, '0');
  return `00000000-0000-4000-8000-${hex}`;
}

export class InMemoryDb
  implements OutboxPort, WorkflowPort, TaskReader, NotificationPort, NoticeReader
{
  /** Milliseconds; tests move it to expire locks and backoff. */
  clock = 1_000_000;

  readonly events = new Map<string, StoredEvent>();
  readonly ledger = new Set<string>();
  readonly rules: StoredRule[] = [];
  readonly tasksByKey = new Map<string, StoredTask>();
  readonly tasks = new Map<string, TaskSnapshot>();
  readonly notifications = new Map<string, StoredNotification>();
  readonly notificationKeys = new Map<string, string>();
  readonly deliveries = new Map<string, StoredDelivery>();
  readonly deliveryKeys = new Map<string, string>();
  readonly notices = new Map<string, NoticeSnapshot>();
  readonly noticeAudience = new Map<string, string[]>();
  /** Task id -> recipients, as task_recipient_person_ids would return them. */
  readonly taskRecipients = new Map<string, string[]>();
  readonly activeMembers = new Set<string>();
  readonly emails = new Map<string, string>();
  readonly pushDevices = new Map<
    string,
    (PushTarget & { personId: string; disabled: boolean })[]
  >();
  readonly disabledPushIds: string[] = [];
  readonly turnedOff = new Set<string>(); // `${personId}:${channel}`

  /** Counts of calls, so tests can assert "ran once", "not called". */
  readonly calls = {
    createTaskFromEvent: 0,
    createNotification: 0,
    recordHandler: 0,
  };

  // --- setup helpers -------------------------------------------------------

  addMember(personId: string, opts: { email?: string; push?: boolean } = {}): void {
    this.activeMembers.add(personId);
    if (opts.email) this.emails.set(personId, opts.email);
    if (opts.push) {
      this.pushDevices.set(personId, [
        {
          id: fakeId(),
          personId,
          disabled: false,
          endpoint: `https://push.example.test/${personId}`,
          p256dh: 'p256dh-placeholder-value-0000',
          authSecret: 'auth-secret-placeholder',
        },
      ]);
    }
  }

  emit(
    type: string,
    entityId: string,
    payload: Record<string, unknown> = {},
    entityTable = 'x',
  ): string {
    const id = fakeId();
    this.events.set(id, {
      id,
      organizationId: 'org-1',
      locationId: 'loc-1',
      type,
      schemaVersion: 1,
      entityTable,
      entityId,
      payload,
      correlationId: id,
      attempts: 0,
      status: 'pending',
      nextAttemptAt: this.clock,
      lockedBy: null,
      lockExpiresAt: null,
      lastError: null,
    });
    return id;
  }

  addTask(task: Partial<TaskSnapshot> & { id: string }, recipients: string[] = []): TaskSnapshot {
    const full: TaskSnapshot = {
      title: 'Check the doors',
      status: 'open',
      priority: 'normal',
      assignedPersonId: null,
      assignedJobTitleId: null,
      ...task,
    };
    this.tasks.set(full.id, full);
    this.taskRecipients.set(full.id, recipients);
    return full;
  }

  // --- OutboxPort ----------------------------------------------------------

  async claim(worker: string, limit: number, lockSeconds: number): Promise<OutboxEvent[]> {
    const due = [...this.events.values()]
      .filter((e) => {
        if (e.status === 'pending') return e.nextAttemptAt <= this.clock;
        return (
          e.status === 'processing' &&
          e.lockExpiresAt !== null &&
          e.lockExpiresAt < this.clock &&
          e.attempts < MAX_OUTBOX_ATTEMPTS
        );
      })
      .slice(0, limit);
    for (const e of due) {
      e.status = 'processing';
      e.attempts += 1;
      e.lockedBy = worker;
      e.lockExpiresAt = this.clock + lockSeconds * 1000;
    }
    return due.map(({ status, nextAttemptAt, lockedBy, lockExpiresAt, lastError, ...event }) => {
      void [status, nextAttemptAt, lockedBy, lockExpiresAt, lastError];
      return { ...event };
    });
  }

  async complete(eventId: string, worker: string): Promise<boolean> {
    const e = this.events.get(eventId);
    if (!e || e.status !== 'processing' || e.lockedBy !== worker) return false;
    e.status = 'done';
    e.lockedBy = null;
    e.lockExpiresAt = null;
    return true;
  }

  async fail(eventId: string, worker: string, error: string): Promise<'pending' | 'dead' | null> {
    const e = this.events.get(eventId);
    if (!e || e.status !== 'processing' || e.lockedBy !== worker) return null;
    const dead = e.attempts >= MAX_OUTBOX_ATTEMPTS;
    e.status = dead ? 'dead' : 'pending';
    e.nextAttemptAt = this.clock + Math.min(2 ** (e.attempts - 1), 360) * MINUTE;
    e.lastError = error.slice(0, 2000);
    e.lockedBy = null;
    e.lockExpiresAt = null;
    return e.status;
  }

  async handlersDone(eventId: string): Promise<string[]> {
    return [...this.ledger]
      .filter((k) => k.startsWith(`${eventId}|`))
      .map((k) => k.slice(eventId.length + 1))
      .sort();
  }

  async recordHandler(eventId: string, handler: string): Promise<boolean> {
    this.calls.recordHandler += 1;
    const key = `${eventId}|${handler}`;
    if (this.ledger.has(key)) return false;
    this.ledger.add(key);
    return true;
  }

  // --- WorkflowPort / TaskReader ------------------------------------------

  async matchRules(eventId: string): Promise<MatchedRule[]> {
    const event = this.events.get(eventId);
    if (!event) return [];
    return this.rules
      .filter((r) => r.enabled && r.eventType === event.type && (r.matches?.(event) ?? true))
      .map((r) => ({ ruleId: r.id, taskTemplateId: r.templateId }));
  }

  async createTaskFromEvent(eventId: string, ruleId: string): Promise<string | null> {
    this.calls.createTaskFromEvent += 1;
    const match = (await this.matchRules(eventId)).find((m) => m.ruleId === ruleId);
    if (!match) return null;
    const key = `${eventId}|${match.taskTemplateId}`;
    const existing = this.tasksByKey.get(key);
    if (existing) return existing.id;
    const id = fakeId();
    const task: StoredTask = {
      id,
      title: 'Rule task',
      status: 'open',
      priority: 'normal',
      assignedPersonId: null,
      assignedJobTitleId: null,
      sourceEventId: eventId,
      templateId: match.taskTemplateId,
    };
    this.tasksByKey.set(key, task);
    this.tasks.set(id, task);
    this.taskRecipients.set(id, []);
    return id;
  }

  async emitOverdueEvents(): Promise<number> {
    return 0;
  }

  async getTask(taskId: string): Promise<TaskSnapshot | null> {
    return this.tasks.get(taskId) ?? null;
  }

  // --- NotificationPort / NoticeReader ------------------------------------

  async createNotification(
    input: CreateNotificationInput | TaskNotificationInput,
  ): Promise<string | null> {
    this.calls.createNotification += 1;
    if (!this.activeMembers.has(input.personId)) return null;
    const key = `${input.eventId}|${input.personId}|${input.kind}`;
    const existing = this.notificationKeys.get(key);
    if (existing) return existing;
    const id = fakeId();
    const urgency = input.urgency ?? 'normal';
    this.notificationKeys.set(key, id);
    this.notifications.set(id, {
      id,
      personId: input.personId,
      kind: input.kind,
      title: input.title,
      body: input.body ?? null,
      linkPath: input.linkPath ?? null,
      urgency,
      sourceEventId: input.eventId,
    });
    for (const channel of ['in_app', 'email', 'push'] as const) {
      const off = urgency !== 'critical' && this.turnedOff.has(`${input.personId}:${channel}`);
      const noDevice =
        channel === 'push' &&
        !(this.pushDevices.get(input.personId) ?? []).some((d) => !d.disabled);
      const dkey = `${id}|${channel}`;
      const did = fakeId();
      this.deliveryKeys.set(dkey, did);
      this.deliveries.set(did, {
        id: did,
        notificationId: id,
        personId: input.personId,
        channel,
        status: channel === 'in_app' ? 'sent' : off || noDevice ? 'skipped' : 'pending',
        attempts: 0,
        nextAttemptAt: this.clock,
        lockedBy: null,
        lockExpiresAt: null,
        lastError: null,
        providerMessageId: null,
      });
    }
    return id;
  }

  async noticeAudiencePersonIds(noticeId: string): Promise<string[]> {
    return (this.noticeAudience.get(noticeId) ?? []).filter((p) => this.activeMembers.has(p));
  }

  async taskRecipientPersonIds(taskId: string): Promise<string[]> {
    return this.taskRecipients.get(taskId) ?? [];
  }

  async getNotice(noticeId: string): Promise<NoticeSnapshot | null> {
    return this.notices.get(noticeId) ?? null;
  }

  // --- DeliveryPort --------------------------------------------------------

  /** The delivery side of the database (its `claim` has a channel, unlike the outbox's). */
  readonly delivery: DeliveryPort = {
    claim: async (worker, limit, lockSeconds, channel) => {
      const due = [...this.deliveries.values()]
        .filter(
          (d) =>
            d.status === 'pending' &&
            d.channel === channel &&
            d.nextAttemptAt <= this.clock &&
            (d.lockExpiresAt === null || d.lockExpiresAt < this.clock) &&
            d.attempts < MAX_DELIVERY_ATTEMPTS,
        )
        .slice(0, limit);
      for (const d of due) {
        d.attempts += 1;
        d.lockedBy = worker;
        d.lockExpiresAt = this.clock + lockSeconds * 1000;
      }
      return due.map((d): Delivery => ({
        id: d.id,
        organizationId: 'org-1',
        notificationId: d.notificationId,
        personId: d.personId,
        channel: d.channel,
        attempts: d.attempts,
      }));
    },
    complete: async (id, worker, providerMessageId) => {
      const d = this.deliveries.get(id);
      if (!d || d.status !== 'pending' || d.lockedBy !== worker) return false;
      d.status = 'sent';
      d.providerMessageId = providerMessageId ?? null;
      d.lockedBy = null;
      d.lockExpiresAt = null;
      return true;
    },
    fail: async (id, worker, error, permanent) => {
      const d = this.deliveries.get(id);
      if (!d || d.status !== 'pending' || d.lockedBy !== worker) return null;
      d.status = permanent || d.attempts >= MAX_DELIVERY_ATTEMPTS ? 'failed' : 'pending';
      d.nextAttemptAt = this.clock + Math.min(2 ** (d.attempts - 1), 360) * MINUTE;
      d.lastError = error;
      d.lockedBy = null;
      d.lockExpiresAt = null;
      return d.status;
    },
    skip: async (id, worker, reason) => {
      const d = this.deliveries.get(id);
      if (!d || d.status !== 'pending' || d.lockedBy !== worker) return false;
      d.status = 'skipped';
      d.lastError = reason;
      d.lockedBy = null;
      d.lockExpiresAt = null;
      return true;
    },
    disablePushSubscription: async (id) => {
      this.disabledPushIds.push(id);
      for (const list of this.pushDevices.values()) {
        for (const device of list) if (device.id === id) device.disabled = true;
      }
      return true;
    },
    getNotification: async (_org, notificationId): Promise<NotificationContent | null> => {
      const n = this.notifications.get(notificationId);
      return n ? { title: n.title, body: n.body, linkPath: n.linkPath, urgency: n.urgency } : null;
    },
    getPersonEmail: async (_org, personId) => this.emails.get(personId) ?? null,
    getPushTargets: async (_org, personId) =>
      (this.pushDevices.get(personId) ?? [])
        .filter((d) => !d.disabled)
        .map(({ id, endpoint, p256dh, authSecret }) => ({ id, endpoint, p256dh, authSecret })),
  };
}
