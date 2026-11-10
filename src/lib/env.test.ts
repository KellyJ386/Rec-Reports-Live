import { describe, expect, it } from 'vitest';
import { publicEnvSchema, serverEnvSchema } from './env';

const valid = {
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
