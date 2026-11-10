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
