'use server';

import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { requireOrgMember } from '@/lib/auth/guards';
import { requireUser } from '@/lib/auth/session';
import { clearActivity } from '@/lib/auth/activity-server';
import { ACTIVE_ORG_COOKIE } from '@/lib/auth/active-org';
import { switchOrganizationSchema } from '@/lib/auth/schemas';

/** POST only (Server Action). Ends the session and forgets the active organization. */
export async function signOut() {
  const supabase = await createClient();
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
