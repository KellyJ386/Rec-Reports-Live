import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';

export const metadata = { title: 'Admin | Rec Reports' };

export default async function AdminLayout({ children }: { children: React.ReactNode }) {
  const { orgName, access } = await requireAdminArea();
  return (
    <>
      <header>
        <p>
          <Link href="/app">Home</Link> | <Link href="/app/admin">Admin</Link> | {orgName}
        </p>
        <nav aria-label="Admin">
          <ul>
            {access.canLocations ? (
              <li>
                <Link href="/app/admin/locations">Locations</Link>
              </li>
            ) : null}
            {access.canSpaces ? (
              <li>
                <Link href="/app/admin/spaces">Spaces and closures</Link>
              </li>
            ) : null}
            {access.canSpaceKinds ? (
              <li>
                <Link href="/app/admin/space-kinds">Space kinds</Link>
              </li>
            ) : null}
            {access.canPeople ? (
              <li>
                <Link href="/app/admin/people">People</Link>
              </li>
            ) : null}
            {access.canPeople ? (
              <li>
                <Link href="/app/admin/roles">Roles</Link>
              </li>
            ) : null}
            {access.isOrgAdmin ? (
              <li>
                <Link href="/app/admin/job-titles">Job titles</Link>
              </li>
            ) : null}
            {access.canAudit ? (
              <li>
                <Link href="/app/admin/audit">Audit log</Link>
              </li>
            ) : null}
            {access.isOrgAdmin ? (
              <li>
                <Link href="/app/admin/settings">Organization settings</Link>
              </li>
            ) : null}
          </ul>
        </nav>
      </header>
      {children}
    </>
  );
}
