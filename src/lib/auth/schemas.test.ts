import { describe, expect, it } from 'vitest';
import {
  confirmEnrollSchema,
  confirmTypeSchema,
  forgotPasswordSchema,
  moduleKeySchema,
  removeFactorSchema,
  resetPasswordSchema,
  signInSchema,
  switchOrganizationSchema,
  totpCodeSchema,
  verifyCodeSchema,
} from './schemas';

describe('signInSchema', () => {
  it('normalises the email', () => {
    const r = signInSchema.parse({ email: '  Ann@Example.COM ', password: 'x' });
    expect(r.email).toBe('ann@example.com');
  });
  it('rejects bad email and empty password', () => {
    expect(signInSchema.safeParse({ email: 'nope', password: 'x' }).success).toBe(false);
    expect(signInSchema.safeParse({ email: 'a@b.co', password: '' }).success).toBe(false);
    expect(signInSchema.safeParse({ email: 'a@b.co', password: null }).success).toBe(false);
  });
});

describe('forgotPasswordSchema', () => {
  it('requires a valid email', () => {
    expect(forgotPasswordSchema.safeParse({ email: '' }).success).toBe(false);
    expect(forgotPasswordSchema.safeParse({ email: 'a@b.co' }).success).toBe(true);
  });
});

describe('resetPasswordSchema', () => {
  const ok = 'correct horse battery';
  it('accepts matching long passwords', () => {
    expect(resetPasswordSchema.safeParse({ password: ok, confirmPassword: ok }).success).toBe(true);
  });
  it('rejects short, mismatched and over-72-byte passwords', () => {
    expect(
      resetPasswordSchema.safeParse({ password: 'short', confirmPassword: 'short' }).success,
    ).toBe(false);
    expect(resetPasswordSchema.safeParse({ password: ok, confirmPassword: ok + '!' }).success).toBe(
      false,
    );
    const long = 'é'.repeat(40); // 80 bytes
    expect(resetPasswordSchema.safeParse({ password: long, confirmPassword: long }).success).toBe(
      false,
    );
  });
});

describe('other schemas', () => {
  it('switchOrganization needs a uuid', () => {
    expect(switchOrganizationSchema.safeParse({ organizationId: 'x' }).success).toBe(false);
    expect(
      switchOrganizationSchema.safeParse({ organizationId: '11111111-1111-4111-8111-111111111111' })
        .success,
    ).toBe(true);
  });
  it('confirm types are limited', () => {
    expect(confirmTypeSchema.safeParse('recovery').success).toBe(true);
    expect(confirmTypeSchema.safeParse('magiclink').success).toBe(false);
  });
  it('module keys match the database check', () => {
    expect(moduleKeySchema.safeParse('people_roles').success).toBe(true);
    expect(moduleKeySchema.safeParse("x'; drop").success).toBe(false);
  });
});

describe('totpCodeSchema and friends', () => {
  it('accepts six digits, ignoring spaces and dashes', () => {
    expect(totpCodeSchema.parse('123456')).toBe('123456');
    expect(totpCodeSchema.parse(' 123 456 ')).toBe('123456');
    expect(totpCodeSchema.parse('123-456')).toBe('123456');
  });
  it('rejects anything else', () => {
    for (const bad of ['', '12345', '1234567', 'abcdef', '12345a', '١٢٣٤٥٦']) {
      expect(totpCodeSchema.safeParse(bad).success, bad).toBe(false);
    }
    expect(totpCodeSchema.safeParse(123456).success).toBe(false);
  });
  it('checks the factor id is a UUID', () => {
    expect(confirmEnrollSchema.safeParse({ factorId: 'nope', code: '123456' }).success).toBe(false);
    expect(
      removeFactorSchema.safeParse({
        factorId: '11111111-1111-4111-8111-111111111111',
        code: '123456',
      }).success,
    ).toBe(true);
    expect(verifyCodeSchema.safeParse({ code: '12' }).success).toBe(false);
  });
});
