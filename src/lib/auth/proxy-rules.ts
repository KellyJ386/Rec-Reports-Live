/** Pure routing rules for src/proxy.ts. Convenience only: pages and actions still call require* helpers. */
export function proxyRedirect(pathname: string, search: string, signedIn: boolean): string | null {
  const inApp = pathname === '/app' || pathname.startsWith('/app/');
  if (inApp && !signedIn) {
    return `/sign-in?next=${encodeURIComponent(pathname + search)}`;
  }
  if (pathname === '/sign-in/verify' && !signedIn) return '/sign-in';
  if (pathname === '/sign-in' && signedIn) return '/app';
  return null;
}
