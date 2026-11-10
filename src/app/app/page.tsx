import { getActiveOrganization, getSessionContext } from '@/lib/auth/session';
import { signOut, switchOrganization } from './actions';

export default async function AppHomePage() {
  const ctx = await getSessionContext();
  const active = await getActiveOrganization();
  const orgName = (id: string) =>
    ctx.memberships.find((m) => m.organizationId === id)?.organizationName ?? id;

  return (
    <main>
      <h1>Rec Reports</h1>
      <p>
        Signed in as {ctx.email ?? 'unknown email'}
        {ctx.isPlatformAdmin ? ' (platform admin)' : ''}.
      </p>

      <h2>Organization</h2>
      {ctx.memberships.length === 0 ? (
        <p>You are not a member of any organization yet. Ask an admin to add you.</p>
      ) : (
        <>
          <p>Working in: {active ? active.organizationName : 'none chosen'}</p>
          {ctx.memberships.length > 1 ? (
            <form action={switchOrganization}>
              <label>
                Switch to{' '}
                <select name="organizationId" defaultValue={active?.organizationId ?? ''}>
                  {active ? null : (
                    <option value="" disabled>
                      Choose one
                    </option>
                  )}
                  {ctx.memberships.map((m) => (
                    <option key={m.organizationId} value={m.organizationId}>
                      {m.organizationName}
                    </option>
                  ))}
                </select>
              </label>{' '}
              <button type="submit">Switch</button>
            </form>
          ) : null}
        </>
      )}

      <h2>Your roles</h2>
      {ctx.roleAssignments.length === 0 ? (
        <p>No roles assigned.</p>
      ) : (
        <ul>
          {ctx.roleAssignments.map((a) => (
            <li key={`${a.organizationId}:${a.roleKey}:${a.locationId ?? 'org'}`}>
              {orgName(a.organizationId)}: {a.roleName} at {a.locationName ?? 'all locations'}
            </li>
          ))}
        </ul>
      )}

      <form action={signOut}>
        <button type="submit">Sign out</button>
      </form>
    </main>
  );
}
