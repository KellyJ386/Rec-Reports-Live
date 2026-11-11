// Pure parsing for /auth/confirm. The page (GET) only reads these values to render a
// button; the Server Action (POST) reads them again from the form and does the verification.
import { confirmTypeSchema } from './schemas';
import { safeNextPath } from './redirect';

export type ConfirmRequest =
  | { kind: 'otp'; tokenHash: string; type: 'recovery' | 'invite' | 'email'; next: string }
  | { kind: 'code'; code: string; next: string };

const MAX_TOKEN = 512;

function text(value: unknown): string | null {
  if (Array.isArray(value)) return text(value[0]);
  if (typeof value !== 'string') return null;
  const t = value.trim();
  return t.length > 0 && t.length <= MAX_TOKEN ? t : null;
}

/** A token_hash+type pair or a PKCE code, with a validated same-origin `next`. Null when neither. */
export function parseConfirmRequest(
  input: Record<string, unknown>,
  fallbackNext: string = '/reset-password',
): ConfirmRequest | null {
  const next = safeNextPath(typeof input.next === 'string' ? input.next : null, fallbackNext);
  const tokenHash = text(input.token_hash);
  const type = confirmTypeSchema.safeParse(text(input.type));
  if (tokenHash && type.success) return { kind: 'otp', tokenHash, type: type.data, next };
  const code = text(input.code);
  if (code) return { kind: 'code', code, next };
  return null;
}

/**
 * Plain words for what pressing the button will do. The address the link was sent to is not
 * available before the token is verified (it is inside the token, which is checked only when
 * the button is pressed), so the page cannot name the account. It says what kind of link this
 * is, and that it acts on the account the link was sent to.
 */
export function describeConfirm(request: ConfirmRequest): {
  heading: string;
  lines: string[];
  button: string;
} {
  const kind = request.kind === 'otp' ? request.type : 'code';
  const unknownAccount = 'We cannot show which account until you continue.';
  switch (kind) {
    case 'recovery':
      return {
        heading: 'Reset your password',
        lines: [
          'This link signs you in to the account it was sent to, so you can choose a new password for it.',
          unknownAccount,
        ],
        button: 'Continue and choose a new password',
      };
    case 'invite':
      return {
        heading: 'Accept your invite',
        lines: [
          'This link signs you in to the account that was created for you, so you can choose a password.',
          unknownAccount,
        ],
        button: 'Accept invite',
      };
    case 'email':
      return {
        heading: 'Sign in with this link',
        lines: ['This link signs you in to the account it was sent to.', unknownAccount],
        button: 'Sign in',
      };
    default:
      return {
        heading: 'Finish signing in',
        lines: ['This link signs you in to the account it was sent to.', unknownAccount],
        button: 'Continue',
      };
  }
}

/**
 * After a link is verified: did it replace a different person's session in this browser? That
 * is the login-CSRF case (a link planted to sign someone into the wrong account), and the person
 * is told. The same person re-confirming a link is not a switch.
 */
export function sessionSwitch(
  previousUserId: string | null | undefined,
  verifiedUserId: string | null | undefined,
): 'none' | 'switched' {
  if (!previousUserId || !verifiedUserId) return 'none';
  return previousUserId === verifiedUserId ? 'none' : 'switched';
}
