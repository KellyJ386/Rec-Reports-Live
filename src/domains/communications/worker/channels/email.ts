import { OUTBOUND_TIMEOUT_MS } from '@/lib/cron/budget';
import { buildEmail } from '../payloads';
import type { DeliveryChannel, DeliveryPort, SendResult } from '../types';

/**
 * Email through Resend's HTTP API (no SDK).
 *
 * Cost: Resend's free tier is the default and is enough for the pilot. As of this writing it
 * allows 3,000 emails a month and 100 a day, one sending domain, and a low request rate (a few
 * calls a second); check resend.com/pricing for the current numbers. Over the daily limit Resend
 * answers 429, which this channel treats as "retry later" (backoff, five attempts, then failed).
 * Nothing here requires a paid plan, and with no API key the channel skips instead of failing.
 */
export interface EmailConfig {
  apiKey?: string;
  /** For example `Rec Reports <alerts@your-domain.example>`; the domain must be verified in Resend. */
  from?: string;
}

export const RESEND_ENDPOINT = 'https://api.resend.com/emails';

export interface EmailChannelDeps {
  config: EmailConfig;
  siteUrl: string;
  people: Pick<DeliveryPort, 'getPersonEmail'>;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export function createEmailChannel(deps: EmailChannelDeps): DeliveryChannel {
  const doFetch = deps.fetchImpl ?? fetch;
  const timeoutMs = deps.timeoutMs ?? OUTBOUND_TIMEOUT_MS;

  return {
    channel: 'email',
    async send({ delivery, notification }): Promise<SendResult> {
      const { apiKey, from } = deps.config;
      if (!apiKey || !from) return { outcome: 'skipped', reason: 'email not configured' };

      const to = await deps.people.getPersonEmail(delivery.organizationId, delivery.personId);
      if (!to) return { outcome: 'skipped', reason: 'no email address' };

      const message = buildEmail(notification, deps.siteUrl);
      let response: Response;
      try {
        response = await doFetch(RESEND_ENDPOINT, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            // Resend de-duplicates repeated sends with the same key for 24 hours: a crash after
            // the send but before complete_notification_delivery cannot mail the person twice.
            'Idempotency-Key': `notification-delivery/${delivery.id}`,
          },
          body: JSON.stringify({
            from,
            to: [to],
            subject: message.subject,
            text: message.text,
            html: message.html,
          }),
          signal: AbortSignal.timeout(timeoutMs),
          cache: 'no-store',
        });
      } catch (error) {
        const timedOut = error instanceof Error && error.name === 'TimeoutError';
        return { outcome: 'retry', error: timedOut ? 'resend_timeout' : 'resend_network' };
      }

      if (response.ok) {
        let id: string | undefined;
        try {
          const body: unknown = await response.json();
          if (
            typeof body === 'object' &&
            body !== null &&
            typeof (body as { id?: unknown }).id === 'string'
          ) {
            id = (body as { id: string }).id;
          }
        } catch {
          // The mail was accepted; a body we cannot read is not a failure.
        }
        return { outcome: 'sent', providerMessageId: id };
      }
      // Drain the body so the connection can be reused; never log or store it.
      await response.body?.cancel().catch(() => undefined);
      // 400/422: the address or message is invalid, so retrying cannot help.
      if (response.status === 400 || response.status === 422) {
        return { outcome: 'failed', error: `resend_${response.status}` };
      }
      // 401/403 (key or domain problem), 429 (rate or daily limit), 5xx: try again later.
      return { outcome: 'retry', error: `resend_${response.status}` };
    },
  };
}
