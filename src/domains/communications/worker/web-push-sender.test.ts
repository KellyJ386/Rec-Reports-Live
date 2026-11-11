import { describe, expect, it, vi } from 'vitest';

vi.mock('web-push', () => ({
  generateRequestDetails: vi.fn(() => ({
    endpoint: 'https://fcm.googleapis.com/fcm/send/abc',
    method: 'POST',
    headers: { TTL: '86400' },
    body: Buffer.from('encrypted'),
  })),
}));

import { PushHttpError, createWebPushSender } from './web-push-sender';

const vapid = { subject: 'mailto:ops@example.com', publicKey: 'pub', privateKey: 'priv' };
const target = {
  id: 's1',
  endpoint: 'https://fcm.googleapis.com/fcm/send/abc',
  p256dh: 'p',
  authSecret: 'a',
};
const options = { urgency: 'normal' as const, ttlSeconds: 60, timeoutMs: 50 };

describe('web push sender', () => {
  it('sends the encrypted request with an abort signal and accepts 201', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 201 }));
    await createWebPushSender(vapid, fetchImpl as unknown as typeof fetch)(target, '{}', options);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://fcm.googleapis.com/fcm/send/abc');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(init.redirect).toBe('error');
  });

  it('really aborts the request at the timeout', async () => {
    let aborted = false;
    const fetchImpl = vi.fn(
      (_url: string, init: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            aborted = true;
            reject(init.signal?.reason);
          });
        }),
    );
    await expect(
      createWebPushSender(vapid, fetchImpl as unknown as typeof fetch)(target, '{}', options),
    ).rejects.toBeTruthy();
    expect(aborted).toBe(true);
  });

  it('throws an error that carries the status, so 404 and 410 can disable the device', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 410 }));
    const error = await createWebPushSender(vapid, fetchImpl as unknown as typeof fetch)(
      target,
      '{}',
      options,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(PushHttpError);
    expect((error as PushHttpError).statusCode).toBe(410);
  });
});
