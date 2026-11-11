// Cookie attributes for the Supabase session cookies. Pure, so it is unit tested.
//
// @supabase/ssr defaults to httpOnly: false so a browser client can read the tokens. This app
// never creates a browser client (all auth runs in Server Actions, Route Handlers and the
// proxy), so the cookies are made httpOnly: a script injected into a page cannot read them.
// Consequence: a Supabase browser client (createBrowserClient) cannot read the session here.
// If one is ever needed, it needs a new decision, not a flag flip.
import type { CookieOptionsWithName } from '@supabase/ssr';

export function authCookieOptions(
  isProduction: boolean = process.env.NODE_ENV === 'production',
): CookieOptionsWithName {
  return { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/' };
}
