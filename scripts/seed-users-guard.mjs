// Pure decision for scripts/seed-users.mjs: may a pre-existing auth user be linked to a
// person? An outsider could have registered the same email before the seed ran, so linking
// by email alone would hand them the person's access.

/**
 * @param {{ email_confirmed_at?: string | null, confirmed_at?: string | null } | null | undefined} user
 * @param {boolean} linkExisting whether --link-existing was passed
 * @returns {{ link: true } | { link: false, reason: string }}
 */
export function canLinkExistingUser(user, linkExisting) {
  if (!user) return { link: false, reason: 'no such user' };
  if (!linkExisting) {
    return { link: false, reason: 'already registered; pass --link-existing to link it' };
  }
  if (!user.email_confirmed_at && !user.confirmed_at) {
    return { link: false, reason: 'already registered but its email is not confirmed' };
  }
  return { link: true };
}
