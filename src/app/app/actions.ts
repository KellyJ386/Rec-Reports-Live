'use server';

import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { requireOrgMember } from '@/lib/auth/guards';
import { requireUser } from '@/lib/auth/session';
import { clearActivity } from '@/lib/auth/activity-server';
import { ACTIVE_ORG_COOKIE } from '@/lib/auth/active-org';
import { switchOrganizationSchema } from '@/lib/auth/schemas';
import { deletePushSubscription, parsePushEndpoint } from '@/domains/communications';

/**
 * POST only (Server Action). Removes this device's push subscription (when the browser sent its
 * endpoint), then ends the session and forgets the active organization.
 *
 * The endpoint comes from a small client step (SignOutForm) that reads the browser's push
 * subscription and unsubscribes it. With JavaScript off the field is empty and sign-out is just
 * the plain form post: it never depends on the push step. The delete runs while the session is
 * still valid (it is the caller's own row, under RLS), for every organization the person is in,
 * and any failure is ignored: signing out always completes.
 */
export async function signOut(formData?: FormData) {
  const supabase = await createClient();
  const endpoint = parsePushEndpoint(formData?.get('push_endpoint'));
  if (endpoint) {
    try {
      const orgs = await supabase.rpc('auth_org_ids');
      const ids = Array.isArray(orgs.data) ? orgs.data.filter((v) => typeof v === 'string') : [];
      for (const orgId of ids) await deletePushSubscription(orgId, endpoint);
    } catch {
      // Best effort. A leftover row points at an endpoint the browser has already dropped.
    }
  }
  await supabase.auth.signOut();
  (await cookies()).delete(ACTIVE_ORG_COOKIE);
  await clearActivity();
  redirect('/sign-in');
}

/** Stores the chosen organization, after checking it against the user's real memberships. */
export async function switchOrganization(formData: FormData) {
  await requireUser();
  const parsed = switchOrganizationSchema.safeParse({
    organizationId: formData.get('organizationId'),
  });
  if (!parsed.success) redirect('/app');
  const membership = await requireOrgMember(parsed.data.organizationId);
  (await cookies()).set(ACTIVE_ORG_COOKIE, membership.organizationId, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 60 * 60 * 24 * 365,
  });
  redirect('/app');
}
