import { describe, expect, it } from 'vitest';
import { resolveDeliveryConfig } from './delivery-config';

const keys = { NEXT_PUBLIC_VAPID_PUBLIC_KEY: 'pub', VAPID_PRIVATE_KEY: 'priv' };

describe('resolveDeliveryConfig', () => {
  it('leaves both channels unconfigured with no settings', () => {
    const c = resolveDeliveryConfig({}, 'https://app.example.com');
    expect(c.email).toEqual({ apiKey: undefined, from: undefined });
    expect(c.vapid).toBeNull();
  });
  it('needs both VAPID keys', () => {
    expect(
      resolveDeliveryConfig({ NEXT_PUBLIC_VAPID_PUBLIC_KEY: 'pub' }, 'https://a.example'),
    ).toMatchObject({ vapid: null });
    expect(resolveDeliveryConfig({ VAPID_PRIVATE_KEY: 'priv' }, 'https://a.example')).toMatchObject(
      { vapid: null },
    );
  });
  it('uses SITE_URL as the subject when it is https, VAPID_SUBJECT when given, and none on plain http', () => {
    expect(resolveDeliveryConfig(keys, 'https://a.example').vapid?.subject).toBe(
      'https://a.example',
    );
    expect(
      resolveDeliveryConfig(
        { ...keys, VAPID_SUBJECT: 'mailto:o@a.example' },
        'http://localhost:3000',
      ).vapid?.subject,
    ).toBe('mailto:o@a.example');
    expect(resolveDeliveryConfig(keys, 'http://localhost:3000').vapid).toBeNull();
  });
  it('passes the email settings through', () => {
    expect(
      resolveDeliveryConfig({ RESEND_API_KEY: 'k', EMAIL_FROM: 'a@b.example' }, 'https://a.example')
        .email,
    ).toEqual({
      apiKey: 'k',
      from: 'a@b.example',
    });
  });
});
