import { describe, expect, it } from 'vitest';
import { CODE_RATE_LIMITED, MFA_UNAVAILABLE, WRONG_CODE, mfaErrorMessage } from './mfa-errors';

describe('mfaErrorMessage', () => {
  it('says the code is wrong for verification failures and expired challenges', () => {
    expect(mfaErrorMessage({ code: 'mfa_verification_failed' })).toBe(WRONG_CODE);
    expect(mfaErrorMessage({ code: 'mfa_challenge_expired' })).toBe(WRONG_CODE);
  });
  it('says to wait when rate limited', () => {
    expect(mfaErrorMessage({ code: 'over_request_rate_limit' })).toBe(CODE_RATE_LIMITED);
    expect(mfaErrorMessage({ status: 429 })).toBe(CODE_RATE_LIMITED);
  });
  it('says unavailable for server errors', () => {
    expect(mfaErrorMessage({ status: 503 })).toBe(MFA_UNAVAILABLE);
  });
  it('never echoes the raw message', () => {
    const text = mfaErrorMessage({ code: 'weird', message: 'secret internal detail' });
    expect(text).not.toContain('secret');
    expect(mfaErrorMessage(null)).toBe(WRONG_CODE);
  });
});
