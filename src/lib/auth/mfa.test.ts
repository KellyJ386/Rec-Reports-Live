import { describe, expect, it } from 'vitest';
import { decideMfaStep, mfaStepPath, normalizeAal } from './mfa';
import { isAdminTier } from './admin-tier';

describe('decideMfaStep', () => {
  it('needs nothing once the session is aal2', () => {
    for (const needsMfa of [true, false]) {
      expect(decideMfaStep({ aal: 'aal2', needsMfa, hasVerifiedFactor: true })).toBe('none');
    }
  });
  it('asks admins with a verified factor for the code', () => {
    expect(decideMfaStep({ aal: 'aal1', needsMfa: true, hasVerifiedFactor: true })).toBe('verify');
  });
  it('sends admins without a factor to set one up', () => {
    expect(decideMfaStep({ aal: 'aal1', needsMfa: true, hasVerifiedFactor: false })).toBe('enroll');
  });
  it('asks anyone with a verified factor for the code, whatever needsMfa says', () => {
    // The database now says needsMfa = true for a voluntary factor too; the answer is the same.
    expect(decideMfaStep({ aal: 'aal1', needsMfa: true, hasVerifiedFactor: true })).toBe('verify');
    expect(decideMfaStep({ aal: null, needsMfa: true, hasVerifiedFactor: true })).toBe('verify');
    expect(decideMfaStep({ aal: 'aal1', needsMfa: false, hasVerifiedFactor: true })).toBe('verify');
  });
  it('leaves people with no factor and no admin access alone', () => {
    expect(decideMfaStep({ aal: 'aal1', needsMfa: false, hasVerifiedFactor: false })).toBe('none');
  });
  it('treats an unknown aal as not aal2', () => {
    expect(decideMfaStep({ aal: null, needsMfa: true, hasVerifiedFactor: false })).toBe('enroll');
    expect(normalizeAal('aal2')).toBe('aal2');
    expect(normalizeAal('aal3')).toBeNull();
    expect(normalizeAal(undefined)).toBeNull();
  });
});

describe('mfaStepPath', () => {
  it('maps steps to screens and keeps a safe next', () => {
    expect(mfaStepPath('none')).toBeNull();
    expect(mfaStepPath('verify')).toBe('/sign-in/verify');
    expect(mfaStepPath('enroll')).toBe('/app/security');
    expect(mfaStepPath('verify', '/app/admin/people')).toBe(
      '/sign-in/verify?next=%2Fapp%2Fadmin%2Fpeople',
    );
  });
  it('drops an unsafe next', () => {
    expect(mfaStepPath('verify', 'https://evil.example')).toBe('/sign-in/verify');
    expect(mfaStepPath('enroll', '//evil.example')).toBe('/app/security');
  });
});

describe('isAdminTier', () => {
  it('is true when the database says the session needs two-step', () => {
    expect(isAdminTier({ needsMfa: true, isPlatformAdmin: false, ranks: [] })).toBe(true);
  });
  it('is true for platform admins and rank 80 or more', () => {
    expect(isAdminTier({ needsMfa: false, isPlatformAdmin: true, ranks: [] })).toBe(true);
    expect(isAdminTier({ needsMfa: false, isPlatformAdmin: false, ranks: [10, 80] })).toBe(true);
  });
  it('is false for managers, staff and custom roles below 80', () => {
    expect(isAdminTier({ needsMfa: false, isPlatformAdmin: false, ranks: [50, 10, 79] })).toBe(
      false,
    );
    expect(isAdminTier({ needsMfa: false, isPlatformAdmin: false, ranks: [] })).toBe(false);
  });
});
