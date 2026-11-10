import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  archiveRoleAction,
  restoreRoleAction,
  saveRoleDefaultsAction,
  updateRoleAction,
} from '@/experiences/admin/actions/roles-access';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { guidParam } from '@/experiences/admin/page-params';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { getRole, listModules, listRoleDefaults, permissionLevelSchema } from '@/domains/identity';

const LEVELS = permissionLevelSchema.options;

export default async function RolePage({ params }: { params: Promise<{ roleId: string }> }) {
  const roleId = guidParam((await params).roleId);
  const { orgId, access } = await requireAdminArea('canPeople');
  const [role, modules, defaults] = await Promise.all([
    getRole(orgId, roleId),
    listModules(),
    listRoleDefaults([roleId]),
  ]);
  if (!role.ok) return <ErrorMessage message={role.message} />;
  if (!role.data) notFound();
  if (!modules.ok) return <ErrorMessage message={modules.message} />;
  if (!defaults.ok) return <ErrorMessage message={defaults.message} />;

  const r = role.data;
  const levels = defaults.data[r.id] ?? {};
  const editable = access.isOrgAdmin && r.organization_id !== null;

  return (
    <main>
      <h1>
        {r.name}
        <ArchivedMark archivedAt={r.archived_at} />
      </h1>
      <p>
        <Link href="/app/admin/roles">All roles</Link>
      </p>
      <p>
        {r.organization_id === null ? 'Built-in role' : 'Custom role'}. Rank {r.rank}.
        {r.description ? ` ${r.description}` : ''}
      </p>
      {r.organization_id === null ? <p>Built-in roles cannot be changed.</p> : null}

      {editable ? (
        <>
          <h2>Details</h2>
          <ActionForm action={updateRoleAction} submitLabel="Save">
            <input type="hidden" name="id" value={r.id} />
            <p>
              <label>
                Name <input name="name" defaultValue={r.name} required maxLength={100} />
              </label>
            </p>
            <p>
              <label>
                Rank (1 to 79){' '}
                <input
                  name="rank"
                  type="number"
                  min={1}
                  max={79}
                  step={1}
                  required
                  defaultValue={r.rank}
                />
              </label>
            </p>
            <p>
              <label>
                What it is for (optional){' '}
                <input name="description" defaultValue={r.description ?? ''} maxLength={1000} />
              </label>
            </p>
          </ActionForm>
        </>
      ) : null}

      <h2>Default access by module</h2>
      <p>
        These are the starting levels for anyone with this role. A person can be given a different
        level on their own access page. Levels from lowest: none, view, edit, admin.
      </p>
      {editable ? (
        <ActionForm action={saveRoleDefaultsAction} submitLabel="Save access levels">
          <input type="hidden" name="id" value={r.id} />
          <table>
            <thead>
              <tr>
                <th scope="col">Module</th>
                <th scope="col">Level</th>
              </tr>
            </thead>
            <tbody>
              {modules.data.map((m) => {
                const current = levels[m.key] ?? 'none';
                return (
                  <tr key={m.key}>
                    <th scope="row">
                      <label htmlFor={`level-${m.key}`}>{m.name}</label>
                    </th>
                    <td>
                      <input type="hidden" name={`was:${m.key}`} value={current} />
                      <select id={`level-${m.key}`} name={`level:${m.key}`} defaultValue={current}>
                        {LEVELS.map((l) => (
                          <option key={l} value={l}>
                            {l}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </ActionForm>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Module</th>
              <th scope="col">Level</th>
            </tr>
          </thead>
          <tbody>
            {modules.data.map((m) => (
              <tr key={m.key}>
                <th scope="row">{m.name}</th>
                <td>{levels[m.key] ?? 'none'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {editable ? (
        <>
          <h2>{r.archived_at ? 'Restore' : 'Archive'}</h2>
          {r.archived_at ? (
            <ActionForm action={restoreRoleAction} submitLabel="Restore this role">
              <input type="hidden" name="id" value={r.id} />
            </ActionForm>
          ) : (
            <>
              <p>
                An archived role cannot be given to anyone new. Anyone whose only role is this one
                loses access to the organization.
              </p>
              <ConfirmAction
                action={archiveRoleAction}
                label="Archive this role"
                question="Yes, archive this role"
                fields={{ id: r.id }}
              />
            </>
          )}
        </>
      ) : null}
    </main>
  );
}
