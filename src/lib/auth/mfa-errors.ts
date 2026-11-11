// Pure: plain-language messages for two-step sign-in failures. Never shows the raw error.
export type AuthErrorLike = {
  code?: string | null;
  status?: number | null;
  message?: string | null;
};

export const WRONG_CODE = 'That code is not right. Try again.';
export const CODE_RATE_LIMITED = 'Too many attempts. Try again in a few minutes.';
export const MFA_UNAVAILABLE = 'Two-step sign-in is unavailable right now. Try again in a moment.';

export function mfaErrorMessage(error: AuthErrorLike | null | undefined): string {
  const code = error?.code ?? '';
  switch (code) {
    case 'mfa_verification_failed':
    case 'mfa_challenge_expired':
    case 'validation_failed':
    case 'bad_code':
      return WRONG_CODE;
    case 'over_request_rate_limit':
    case 'over_email_send_rate_limit':
    case 'mfa_verification_rejected':
      return CODE_RATE_LIMITED;
    default:
      if (error?.status === 429) return CODE_RATE_LIMITED;
      if (error?.status !== undefined && error?.status !== null && error.status >= 500) {
        return MFA_UNAVAILABLE;
      }
      return WRONG_CODE;
  }
}
