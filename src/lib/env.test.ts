import { describe, expect, it } from 'vitest';
import {
  adminEnvSchema,
  deliveryEnvSchema,
  missingProductionEnv,
  publicEnvSchema,
  serverEnvSchema,
  siteUrlSchema,
} from './env';

const valid = {
  SITE_URL: 'https://app.example.com',
  NEXT_PUBLIC_SUPABASE_URL: 'https://example.supabase.co',
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: 'publishable-placeholder',
  SUPABASE_SERVICE_ROLE_KEY: 'service-placeholder',
  SESSION_SIGNING_SECRET: 'a-test-secret-that-is-at-least-32-chars',
};

describe('serverEnvSchema', () => {
  it('accepts a complete environment and treats CRON_SECRET as optional', () => {
    const parsed = serverEnvSchema.parse(valid);
    expect(parsed.CRON_SECRET).toBeUndefined();
  });

  it('rejects a missing service role key', () => {
    const rest: Partial<typeof valid> = { ...valid };
    delete rest.SUPABASE_SERVICE_ROLE_KEY;
    expect(serverEnvSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects a missing or short session signing secret', () => {
    const rest: Partial<typeof valid> = { ...valid };
    delete rest.SESSION_SIGNING_SECRET;
    expect(serverEnvSchema.safeParse(rest).success).toBe(false);
    expect(serverEnvSchema.safeParse({ ...valid, SESSION_SIGNING_SECRET: 'short' }).success).toBe(
      false,
    );
  });

  it('rejects a URL that is not a URL and an empty key', () => {
    expect(serverEnvSchema.safeParse({ ...valid, NEXT_PUBLIC_SUPABASE_URL: 'nope' }).success).toBe(
      false,
    );
    expect(
      serverEnvSchema.safeParse({ ...valid, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: '' }).success,
    ).toBe(false);
  });

  it('public schema never includes secrets', () => {
    const parsed = publicEnvSchema.parse(valid);
    expect(Object.keys(parsed).sort()).toEqual([
      'NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY',
      'NEXT_PUBLIC_SUPABASE_URL',
    ]);
  });
});

describe('CRON_SECRET', () => {
  it('must be at least 32 characters when set', () => {
    expect(serverEnvSchema.safeParse({ ...valid, CRON_SECRET: 'x'.repeat(31) }).success).toBe(
      false,
    );
    expect(serverEnvSchema.safeParse({ ...valid, CRON_SECRET: 'x'.repeat(32) }).success).toBe(true);
  });
});

describe('adminEnvSchema', () => {
  it('needs only the Supabase URL and the service-role key', () => {
    const parsed = adminEnvSchema.parse({
      NEXT_PUBLIC_SUPABASE_URL: 'https://example.supabase.co',
      SUPABASE_SERVICE_ROLE_KEY: 'service-placeholder',
    });
    expect(Object.keys(parsed).sort()).toEqual([
      'NEXT_PUBLIC_SUPABASE_URL',
      'SUPABASE_SERVICE_ROLE_KEY',
    ]);
    expect(adminEnvSchema.safeParse({ NEXT_PUBLIC_SUPABASE_URL: 'https://x.co' }).success).toBe(
      false,
    );
  });
});

describe('missingProductionEnv', () => {
  it('is empty for a complete environment, with CRON_SECRET unset allowed', () => {
    expect(missingProductionEnv(valid)).toEqual([]);
  });
  it('names each missing or malformed setting, never a value', () => {
    expect(
      missingProductionEnv({ ...valid, SESSION_SIGNING_SECRET: 'short', SITE_URL: undefined }),
    ).toEqual(['SESSION_SIGNING_SECRET', 'SITE_URL']);
    expect(missingProductionEnv({ ...valid, SUPABASE_SERVICE_ROLE_KEY: '' })).toEqual([
      'SUPABASE_SERVICE_ROLE_KEY',
    ]);
    expect(missingProductionEnv({ ...valid, CRON_SECRET: 'short' })).toEqual(['CRON_SECRET']);
  });
});

describe('siteUrlSchema', () => {
  it('accepts an https origin and normalises a trailing slash', () => {
    expect(siteUrlSchema.parse('https://app.example.com')).toBe('https://app.example.com');
    expect(siteUrlSchema.parse('https://app.example.com/')).toBe('https://app.example.com');
  });
  it('accepts http only for localhost', () => {
    expect(siteUrlSchema.parse('http://localhost:3000')).toBe('http://localhost:3000');
    expect(siteUrlSchema.safeParse('http://app.example.com').success).toBe(false);
  });
  it('rejects paths, queries, credentials, other schemes and junk', () => {
    for (const v of [
      'https://app.example.com/path',
      'https://app.example.com?x=1',
      'https://user:pw@app.example.com',
      'ftp://app.example.com',
      'javascript:alert(1)',
      'not a url',
      '',
      undefined,
    ]) {
      expect(siteUrlSchema.safeParse(v).success, String(v)).toBe(false);
    }
  });
  it('is required in the server environment', () => {
    const rest: Partial<typeof valid> = { ...valid };
    delete rest.SITE_URL;
    expect(serverEnvSchema.safeParse(rest).success).toBe(false);
  });
});

describe('deliveryEnvSchema', () => {
  it('accepts nothing at all: every delivery setting is optional', () => {
    expect(deliveryEnvSchema.parse({})).toEqual({});
  });
  it('treats empty strings (an unfilled KEY= line) as unset', () => {
    const parsed = deliveryEnvSchema.parse({
      RESEND_API_KEY: '',
      EMAIL_FROM: '  ',
      VAPID_PRIVATE_KEY: '',
      VAPID_SUBJECT: '',
    });
    expect(parsed.RESEND_API_KEY).toBeUndefined();
    expect(parsed.EMAIL_FROM).toBeUndefined();
    expect(parsed.VAPID_SUBJECT).toBeUndefined();
  });
  it('accepts mailto: and https: subjects and rejects anything else', () => {
    expect(deliveryEnvSchema.safeParse({ VAPID_SUBJECT: 'mailto:ops@example.com' }).success).toBe(
      true,
    );
    expect(deliveryEnvSchema.safeParse({ VAPID_SUBJECT: 'https://app.example.com' }).success).toBe(
      true,
    );
    expect(deliveryEnvSchema.safeParse({ VAPID_SUBJECT: 'http://app.example.com' }).success).toBe(
      false,
    );
    expect(deliveryEnvSchema.safeParse({ VAPID_SUBJECT: 'ops@example.com' }).success).toBe(false);
  });
});
