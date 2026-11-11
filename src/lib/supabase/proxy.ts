import { createServerClient } from '@supabase/ssr';
import type { Database } from './database.types';
import { NextResponse, type NextRequest } from 'next/server';
import { getPublicEnv } from '@/lib/env';
import { authCookieOptions } from './cookie-options';

/**
 * Refreshes the Supabase auth session on each request and writes any updated
 * cookies to both the request and the response. Called from src/proxy.ts.
 * It makes no access decision itself; it reports whether the token validated (and who the
 * user is) so src/proxy.ts can apply convenience redirects and the idle timeout. Routes and
 * RLS decide access. `response` is a getter: a later sign-out through `supabase` replaces it.
 */
export async function updateSession(request: NextRequest) {
  let response = NextResponse.next({ request });
  const env = getPublicEnv();

  const supabase = createServerClient<Database>(
    env.NEXT_PUBLIC_SUPABASE_URL,
    env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
    {
      cookieOptions: authCookieOptions(),
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet, headers) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          response = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options),
          );
          Object.entries(headers ?? {}).forEach(([key, value]) => response.headers.set(key, value));
        },
      },
    },
  );

  // Validates the token and triggers a refresh when it has expired.
  const { data } = await supabase.auth.getClaims();

  const userId = typeof data?.claims?.sub === 'string' ? data.claims.sub : null;
  return {
    get response() {
      return response;
    },
    supabase,
    userId,
    signedIn: userId !== null,
  };
}
