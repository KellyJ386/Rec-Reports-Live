export const ACTIVE_ORG_COOKIE = 'rr_active_org';

export type OrgChoice = { organizationId: string };

/**
 * Picks the active organization. The cookie value is only a preference: it is
 * honoured only when it matches one of the user's real memberships. With
 * exactly one membership that membership is used. With several memberships
 * and no valid preference, returns null (the caller asks the user to choose).
 */
export function selectActiveOrganization<T extends OrgChoice>(
  memberships: readonly T[],
  cookieValue: string | null | undefined,
): T | null {
  if (cookieValue) {
    const match = memberships.find((m) => m.organizationId === cookieValue);
    if (match) return match;
  }
  if (memberships.length === 1) return memberships[0] ?? null;
  return null;
}
