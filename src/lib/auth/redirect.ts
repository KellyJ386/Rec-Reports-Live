export const DEFAULT_AFTER_SIGN_IN = '/app';

/**
 * Returns `candidate` only when it is a same-origin relative path; otherwise
 * `fallback`. Rejects absolute URLs, protocol-relative (`//host`), backslash
 * tricks, control characters and anything that resolves to another origin.
 */
export function safeNextPath(
  candidate: string | null | undefined,
  fallback: string = DEFAULT_AFTER_SIGN_IN,
): string {
  if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > 2048) {
    return fallback;
  }
  if (!candidate.startsWith('/') || candidate.startsWith('//')) return fallback;
  if (/[\\\u0000-\u001f\u007f]/.test(candidate)) return fallback;
  try {
    const base = 'http://localhost';
    const url = new URL(candidate, base);
    if (url.origin !== base) return fallback;
    if (url.pathname.startsWith('//')) return fallback;
    return url.pathname + url.search + url.hash;
  } catch {
    return fallback;
  }
}
