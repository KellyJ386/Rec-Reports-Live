// Pure: does this session hold admin-tier access (rank >= 80, see docs/SECURITY.md)?
// Admin-tier is the group that must use two-step sign-in and is signed out when idle.

export const ADMIN_TIER_RANK = 80;

/**
 * `needsMfa` is the database's own answer (session_needs_mfa(): admin-tier access that it is
 * ignoring because the session is not aal2). Once the session is aal2 the database stops
 * ignoring it, so platform admin status and the caller's own effective ranks show it directly.
 */
export function isAdminTier(input: {
  needsMfa: boolean;
  isPlatformAdmin: boolean;
  /** Effective ranks of the caller's own assignments (roles.rank, +10 at organization scope). */
  ranks: readonly number[];
}): boolean {
  return (
    input.needsMfa || input.isPlatformAdmin || input.ranks.some((rank) => rank >= ADMIN_TIER_RANK)
  );
}
