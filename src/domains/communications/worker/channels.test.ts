import { describe, expect, it, vi } from 'vitest';
import {
  createChannels,
  createEmailChannel,
  createInAppChannel,
  createPushChannel,
} from './channels';
import type { PushSendOptions } from './channels';
import type { Delivery, NotificationContent, PushTarget } from './types';

const delivery: Delivery = {
  id: 'd1',
  organizationId: 'o1',
  notificationId: 'n1',
  personId: 'p1',
  channel: 'email',
  attempts: 1,
};
const content: NotificationContent = {
  title: 'Overdue: Fix door',
  body: 'This task is past its due time.',
  linkPath: '/app/tasks/t1',
  urgency: 'high',
};
const SITE = 'https://app.example.com';

describe('in_app channel', () => {
  it('has nothing to send and reports sent', async () => {
    expect(await createInAppChannel().send({ delivery, notification: content })).toEqual({
      outcome: 'sent',
    });
  });
});

describe('email channel', () => {
  const people = (email: string | null) => ({ getPersonEmail: vi.fn(async () => email) });
  const make = (
    over: { apiKey?: string; from?: string; email?: string | null; fetchImpl?: typeof fetch } = {},
  ) =>
    createEmailChannel({
      config: {
        apiKey: 'apiKey' in over ? over.apiKey : 'key',
        from: 'from' in over ? over.from : 'Rec Reports <a@example.com>',
      },
      siteUrl: SITE,
      people: people(over.email === undefined ? 'person@example.com' : over.email),
      fetchImpl: over.fetchImpl,
    });
  const send = (c: ReturnType<typeof make>) => c.send({ delivery, notification: content });

  it('skips with "email not configured" when the key or the sender is unset, and never calls out', async () => {
    const fetchImpl = vi.fn();
    const f = fetchImpl as unknown as typeof fetch;
    expect(await send(make({ apiKey: undefined, fetchImpl: f }))).toEqual({
      outcome: 'skipped',
      reason: 'email not configured',
    });
    expect(await send(make({ from: undefined, fetchImpl: f }))).toEqual({
      outcome: 'skipped',
      reason: 'email not configured',
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('skips when the person has no email address', async () => {
    const fetchImpl = vi.fn();
    expect(
      await send(make({ email: null, fetchImpl: fetchImpl as unknown as typeof fetch })),
    ).toEqual({
      outcome: 'skipped',
      reason: 'no email address',
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('posts to Resend with a bearer key, an idempotency key, a timeout, and only the safe content', async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => Response.json({ id: 'resend-1' }));
    const result = await send(make({ fetchImpl: fetchImpl as unknown as typeof fetch }));
    expect(result).toEqual({ outcome: 'sent', providerMessageId: 'resend-1' });
    const [url, init] = fetchImpl.mock.calls[0] ?? [];
    expect(url).toBe('https://api.resend.com/emails');
    const headers = init?.headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer key');
    expect(headers['Idempotency-Key']).toBe('notification-delivery/d1');
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    const body = JSON.parse(String(init?.body));
    expect(body.to).toEqual(['person@example.com']);
    expect(body.subject).toBe('Overdue: Fix door');
    expect(body.text).toContain('https://app.example.com/app/tasks/t1');
    expect(Object.keys(body).sort()).toEqual(['from', 'html', 'subject', 'text', 'to']);
  });

  it('retries on 429, 5xx and auth problems, and fails for good on 400/422', async () => {
    const run = async (status: number) =>
      send(
        make({
          fetchImpl: (async () => new Response('{}', { status })) as unknown as typeof fetch,
        }),
      );
    for (const s of [429, 500, 503, 401, 403]) {
      expect(await run(s)).toEqual({ outcome: 'retry', error: `resend_${s}` });
    }
    for (const s of [400, 422]) {
      expect(await run(s)).toEqual({ outcome: 'failed', error: `resend_${s}` });
    }
  });

  it('retries on a network error or a timeout, naming only the class', async () => {
    const boom = (name: string) =>
      (async () => {
        throw Object.assign(new Error('connect to person@example.com failed'), { name });
      }) as unknown as typeof fetch;
    expect(await send(make({ fetchImpl: boom('TimeoutError') }))).toEqual({
      outcome: 'retry',
      error: 'resend_timeout',
    });
    expect(await send(make({ fetchImpl: boom('TypeError') }))).toEqual({
      outcome: 'retry',
      error: 'resend_network',
    });
  });

  it('still counts a 200 with an unreadable body as sent', async () => {
    const f = (async () => new Response('not json', { status: 200 })) as unknown as typeof fetch;
    expect(await send(make({ fetchImpl: f }))).toEqual({
      outcome: 'sent',
      providerMessageId: undefined,
    });
  });
});

describe('push channel', () => {
  const vapid = { subject: 'mailto:a@example.com', publicKey: 'pub', privateKey: 'priv' };
  const target = (id: string): PushTarget => ({
    id,
    endpoint: `https://push.example/${id}`,
    p256dh: 'k',
    authSecret: 's',
  });
  const make = (opts: {
    vapid?: typeof vapid | null;
    targets?: PushTarget[];
    send?: (t: PushTarget, payload: string, options: PushSendOptions) => Promise<void>;
  }) => {
    const disabled: string[] = [];
    const sender = vi.fn(opts.send ?? (async () => undefined));
    const channel = createPushChannel({
      vapid: opts.vapid === undefined ? vapid : opts.vapid,
      siteUrl: SITE,
      devices: {
        getPushTargets: async () => opts.targets ?? [target('a')],
        disablePushSubscription: async (id) => {
          disabled.push(id);
          return true;
        },
      },
      send: sender,
    });
    return { channel, sender, disabled };
  };
  const send = (c: { channel: ReturnType<typeof make>['channel'] }) =>
    c.channel.send({ delivery: { ...delivery, channel: 'push' }, notification: content });
  const gone = (status: number) => Object.assign(new Error('gone'), { statusCode: status });

  it('skips when VAPID keys are not configured, without reading devices or sending', async () => {
    const m = make({ vapid: null });
    expect(await send(m)).toEqual({ outcome: 'skipped', reason: 'push not configured' });
    expect(m.sender).not.toHaveBeenCalled();
  });

  it('skips when the person has no active device', async () => {
    expect(await send(make({ targets: [] }))).toEqual({
      outcome: 'skipped',
      reason: 'no push device',
    });
  });

  it('sends the payload with high urgency for non-normal notifications and a timeout', async () => {
    const m = make({});
    expect(await send(m)).toEqual({ outcome: 'sent' });
    const [t, payload, options] = m.sender.mock.calls[0] ?? [];
    expect(t?.id).toBe('a');
    expect(JSON.parse(String(payload))).toEqual({
      title: 'Overdue: Fix door',
      body: 'This task is past its due time.',
      url: 'https://app.example.com/app/tasks/t1',
      urgent: false,
    });
    expect(options).toMatchObject({ urgency: 'high' });
    expect(options?.timeoutMs).toBeGreaterThan(0);
  });

  it('on 410 or 404 disables the subscription and fails permanently', async () => {
    for (const status of [410, 404]) {
      const m = make({ send: async () => Promise.reject(gone(status)) });
      expect(await send(m)).toEqual({ outcome: 'failed', error: 'push_subscription_gone' });
      expect(m.disabled).toEqual(['a']);
    }
  });

  it('retries on other errors without disabling anything', async () => {
    for (const status of [500, 429, 403]) {
      const m = make({ send: async () => Promise.reject(gone(status)) });
      expect(await send(m)).toEqual({ outcome: 'retry', error: 'push_error' });
      expect(m.disabled).toEqual([]);
    }
    const m = make({ send: async () => Promise.reject(new Error('socket hang up')) });
    expect((await send(m)).outcome).toBe('retry');
  });

  it('with several devices: sent if any worked (gone ones are disabled), retry if only transient errors remain', async () => {
    const targets = [target('a'), target('b'), target('c')];
    const mixed = make({
      targets,
      send: async (t) => {
        if (t.id === 'a') throw gone(410);
        if (t.id === 'b') throw gone(500);
      },
    });
    expect(await send(mixed)).toEqual({ outcome: 'sent' });
    expect(mixed.disabled).toEqual(['a']);

    const transient = make({
      targets: [target('a'), target('b')],
      send: async (t) => {
        throw gone(t.id === 'a' ? 410 : 503);
      },
    });
    expect(await send(transient)).toEqual({ outcome: 'retry', error: 'push_error' });
  });

  it('gives up on a send that never answers', async () => {
    vi.useFakeTimers();
    try {
      const channel = createPushChannel({
        vapid,
        siteUrl: SITE,
        timeoutMs: 1000,
        devices: {
          getPushTargets: async () => [target('a')],
          disablePushSubscription: async () => true,
        },
        send: () => new Promise<void>(() => undefined),
      });
      const pending = channel.send({ delivery, notification: content });
      await vi.advanceTimersByTimeAsync(1500);
      expect(await pending).toEqual({ outcome: 'retry', error: 'push_error' });
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('createChannels', () => {
  it('builds all three channels', () => {
    const c = createChannels({
      email: { config: {}, siteUrl: SITE, people: { getPersonEmail: async () => null } },
      push: {
        vapid: null,
        siteUrl: SITE,
        devices: { getPushTargets: async () => [], disablePushSubscription: async () => true },
        send: async () => undefined,
      },
    });
    expect(Object.keys(c).sort()).toEqual(['email', 'in_app', 'push']);
    expect(c.email.channel).toBe('email');
    expect(c.push.channel).toBe('push');
  });
});
