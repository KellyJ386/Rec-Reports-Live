import { describe, expect, it } from 'vitest';
import { publicEnvSchema, serverEnvSchema, siteUrlSchema } from './env';

const valid = {
  SITE_URL: 'https://app.example.com',
  NEXT_PUBLIC_SUPABASE_URL: 'https://example.supabase.co',
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: 'publishable-placeholder',
  SUPABASE_SERVICE_ROLE_KEY: 'service-placeholder',
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
