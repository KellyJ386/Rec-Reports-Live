import { redirect } from 'next/navigation';
import type { NextRequest } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { confirmTypeSchema } from '@/lib/auth/schemas';
import { safeNextPath } from '@/lib/auth/redirect';

/**
 * Landing point for Supabase email links.
 *  - ?token_hash=...&type=recovery|invite|email  (email templates pointing here;
 *    works in any browser): verifyOtp.
 *  - ?code=...  (PKCE link from resetPasswordForEmail; needs the code verifier
 *    cookie from the browser that asked): exchangeCodeForSession.
 * `next` is restricted to same-origin relative paths. Any failure goes to
 * /sign-in?error=link with no detail.
 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const next = safeNextPath(params.get('next'), '/reset-password');
  const supabase = await createClient();

  const code = params.get('code');
  const tokenHash = params.get('token_hash');
  const type = confirmTypeSchema.safeParse(params.get('type'));

  let ok = false;
  if (tokenHash && type.success) {
    const { error } = await supabase.auth.verifyOtp({ type: type.data, token_hash: tokenHash });
    ok = !error;
  } else if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    ok = !error;
  }

  redirect(ok ? next : '/sign-in?error=link');
}
