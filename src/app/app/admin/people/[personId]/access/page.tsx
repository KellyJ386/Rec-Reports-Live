import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  addAssignmentAction,
  addPersonJobTitleAction,
  changeAssignmentAction,
  removeAssignmentAction,
  removeOverrideAction,
  removePersonJobTitleAction,
  setOverrideAction,
} from '@/experiences/admin/actions/roles-access';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { guidParam } from '@/experiences/admin/page-params';
import { ErrorMessage } from '@/experiences/admin/ui';
import {
  assignableRoles,
  assignmentRank,
  displayName,
  effectiveLevelKey,
  getPerson,
  getPersonEffectiveLevels,
  isLastActiveAssignment,
  listJobTitles,
  listModules,
  listPersonJobTitles,
  listRoleAssignments,
  listRoles,
  listUserPermissions,
  permissionLevelSchema,
} from '@/domains/identity';
import { listAllLocations } from '@/domains/organizations';

const LEVELS = permissionLevelSchema.options;

export default async function PersonAccessPage({
  params,
}: {
  params: Promise<{ personId: string }>;
}) {
  const personId = guidParam((await params).personId);
  const { orgId, access } = await requireAdminArea('canPeople');

  const [person, assignments, titles, overrides, roles, jobTitles, locations, modules] =
    await Promise.all([
      getPerson(orgId, personId),
      listRoleAssignments(orgId, personId),
      listPersonJobTitles(orgId, personId),
      access.canPeopleAdmin ? listUserPermissions(orgId, personId) : Promise.resolve(null),
      listRoles(orgId),
      listJobTitles(orgId),
      listAllLocations(orgId, { includeArchived: true }),
      listModules(),
    ]);
  if (!person.ok) return <ErrorMessage message={person.message} />;
  if (!person.data) notFound();
  for (const r of [assignments, titles, roles, jobTitles, locations, modules]) {
    if (!r.ok) return <ErrorMessage message={r.message} />;
  }
  if (overrides && !overrides.ok) return <ErrorMessage message={overrides.message} />;
  if (!assignments.ok || !titles.ok || !roles.ok || !jobTitles.ok || !locations.ok || !modules.ok) {
    return null;
  }
  const overrideRows = overrides?.ok ? overrides.data : [];

  const locationName = new Map(locations.data.map((l) => [l.id, l.name]));
  const where = (id: string | null) =>
    id === null ? 'Whole organization' : (locationName.get(id) ?? 'A location');
  const moduleName = new Map(modules.data.map((m) => [m.key, m.name]));
  const archivedLocationIds = new Set(
    locations.data.filter((l) => l.archived_at !== null).map((l) => l.id),
  );

  // "Level now" comes from the database (person_effective_permission), never re-implemented
  // here. Cells: the override modules x (organization scope, the person's assignment
  // locations, the override locations). A refusal shows as "not available".
  const scopes: Array<string | null> = [
    null,
    ...new Set([
      ...assignments.data.flatMap((a) => (a.location_id ? [a.location_id] : [])),
      ...overrideRows.flatMap((o) => (o.location_id ? [o.location_id] : [])),
    ]),
  ];
  const overrideModules = [...new Set(overrideRows.map((o) => o.module_key))];
  const levels =
    overrideRows.length > 0
      ? await getPersonEffectiveLevels(orgId, personId, scopes, overrideModules)
      : new Map<string, null>();
  const levelNow = (locationId: string | null, moduleKey: string): string =>
    levels.get(effectiveLevelKey(locationId, moduleKey)) ?? 'not available';
  const name = displayName(person.data);
  const activeLocations = locations.data.filter((l) => l.archived_at === null);

  return (
    <main>
      <h1>Access for {name}</h1>
      <p>
        <Link href={`/app/admin/people/${personId}`}>Back to {name}</Link>
      </p>

      <h2>Roles</h2>
      {assignments.data.length === 0 ? (
        <p>No roles. This person cannot see anything until they have one.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Role</th>
              <th scope="col">Where</th>
              <th scope="col">Rank</th>
              {access.canPeopleAdmin ? <th scope="col">Change</th> : null}
              {access.canPeopleAdmin ? <th scope="col">Remove</th> : null}
            </tr>
          </thead>
          <tbody>
            {assignments.data.map((a) => (
              <tr key={a.id}>
                <td>{a.role?.name ?? 'A role'}</td>
                <td>{where(a.location_id)}</td>
                <td>{a.role ? assignmentRank(a.role.rank, a.location_id) : ''}</td>
                {access.canPeopleAdmin ? (
                  <td>
                    <details>
                      <summary>Change</summary>
                      <ActionForm action={changeAssignmentAction} submitLabel="Save change">
                        <input type="hidden" name="id" value={a.id} />
                        <input type="hidden" name="person_id" value={personId} />
                        <p>
                          <label>
                            Role{' '}
                            <select name="role_id" required defaultValue={a.role_id}>
                              {assignableRoles(roles.data).map((r) => (
                                <option key={r.id} value={r.id}>
                                  {r.name} (rank {r.rank})
                                </option>
                              ))}
                            </select>
                          </label>{' '}
                          <label>
                            Where{' '}
                            <select name="location_id" defaultValue={a.location_id ?? ''}>
                              <option value="">Whole organization (admin role only)</option>
                              {activeLocations.map((l) => (
                                <option key={l.id} value={l.id}>
                                  {l.name}
                                </option>
                              ))}
                            </select>
                          </label>
                        </p>
                      </ActionForm>
                    </details>
                  </td>
                ) : null}
                {access.canPeopleAdmin ? (
                  <td>
                    <ConfirmAction
                      action={removeAssignmentAction}
                      label="Remove"
                      question={
                        isLastActiveAssignment(assignments.data, a.id, archivedLocationIds)
                          ? `Yes, remove ${a.role?.name ?? 'this role'} (${where(a.location_id)}). This is their last role: they will lose access to the organization.`
                          : `Yes, remove ${a.role?.name ?? 'this role'} (${where(a.location_id)})`
                      }
                      fields={{
                        id: a.id,
                        person_id: personId,
                        ...(isLastActiveAssignment(assignments.data, a.id, archivedLocationIds)
                          ? { confirm_last: 'yes' }
                          : {}),
                      }}
                    />
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {access.canPeopleAdmin ? (
        <>
          <h3>Add a role</h3>
          <ActionForm action={addAssignmentAction} submitLabel="Add role">
            <input type="hidden" name="person_id" value={personId} />
            <p>
              <label>
                Role{' '}
                <select name="role_id" required defaultValue="">
                  <option value="" disabled>
                    Choose one
                  </option>
                  {assignableRoles(roles.data).map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name} (rank {r.rank})
                    </option>
                  ))}
                </select>
              </label>{' '}
              <label>
                Where{' '}
                <select name="location_id" defaultValue="">
                  <option value="">Whole organization (admin role only)</option>
                  {activeLocations.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name}
                    </option>
                  ))}
                </select>
              </label>
            </p>
          </ActionForm>
          <p>
            You can only give a role that ranks below your own, and you cannot change your own
            access.
          </p>
        </>
      ) : null}

      <h2>Job titles</h2>
      <p>Job titles decide who gets a task or message. They do not give access.</p>
      {titles.data.length === 0 ? (
        <p>No job titles.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Job title</th>
              <th scope="col">Where</th>
              <th scope="col">Remove</th>
            </tr>
          </thead>
          <tbody>
            {titles.data.map((t) => (
              <tr key={t.id}>
                <td>{t.job_title?.name ?? 'A job title'}</td>
                <td>{t.location_id === null ? 'Everywhere they work' : where(t.location_id)}</td>
                <td>
                  <ConfirmAction
                    action={removePersonJobTitleAction}
                    label="Remove"
                    question={`Yes, remove ${t.job_title?.name ?? 'this job title'}`}
                    fields={{ id: t.id, person_id: personId }}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h3>Add a job title</h3>
      <ActionForm action={addPersonJobTitleAction} submitLabel="Add job title">
        <input type="hidden" name="person_id" value={personId} />
        <p>
          <label>
            Job title{' '}
            <select name="job_title_id" required defaultValue="">
              <option value="" disabled>
                Choose one
              </option>
              {jobTitles.data.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </label>{' '}
          <label>
            Where{' '}
            <select name="location_id" defaultValue="">
              <option value="">Everywhere they work</option>
              {activeLocations.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          </label>
        </p>
      </ActionForm>
      {access.isOrgAdmin ? (
        <p>
          <Link href="/app/admin/job-titles">Manage the job title list</Link>
        </p>
      ) : null}

      {overrides ? (
        <>
          <h2>Access overrides</h2>
          <p>
            An override replaces the role&apos;s default level for one module, either for the whole
            organization or for one location. It never gives access by itself: the person still
            needs a role there. &quot;Level now&quot; is what the database works out for this person
            today, so it follows archived roles and locations too.
          </p>
          {overrideRows.length === 0 ? (
            <p>No overrides.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th scope="col">Module</th>
                  <th scope="col">Where</th>
                  <th scope="col">Override</th>
                  <th scope="col">Level now</th>
                  <th scope="col">Remove</th>
                </tr>
              </thead>
              <tbody>
                {overrideRows.map((o) => (
                  <tr key={o.id}>
                    <td>{moduleName.get(o.module_key) ?? o.module_key}</td>
                    <td>{where(o.location_id)}</td>
                    <td>{o.level}</td>
                    <td>{levelNow(o.location_id, o.module_key)}</td>
                    <td>
                      <ConfirmAction
                        action={removeOverrideAction}
                        label="Remove"
                        question="Yes, remove this override"
                        fields={{ id: o.id, person_id: personId }}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {overrideModules.length > 0 ? (
            <>
              <h3>Level now where they work</h3>
              <table>
                <thead>
                  <tr>
                    <th scope="col">Module</th>
                    {scopes.map((loc) => (
                      <th scope="col" key={loc ?? 'org'}>
                        {where(loc)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {overrideModules.map((m) => (
                    <tr key={m}>
                      <td>{moduleName.get(m) ?? m}</td>
                      {scopes.map((loc) => (
                        <td key={loc ?? 'org'}>{levelNow(loc, m)}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : null}
          <h3>Set an override</h3>
          <p>Setting one for a module and place that already has an override changes it.</p>
          <ActionForm action={setOverrideAction} submitLabel="Save override">
            <input type="hidden" name="person_id" value={personId} />
            <p>
              <label>
                Module{' '}
                <select name="module_key" required defaultValue="">
                  <option value="" disabled>
                    Choose one
                  </option>
                  {modules.data.map((m) => (
                    <option key={m.key} value={m.key}>
                      {m.name}
                    </option>
                  ))}
                </select>
              </label>{' '}
              <label>
                Level{' '}
                <select name="level" required defaultValue="view">
                  {LEVELS.map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
              </label>{' '}
              <label>
                Where{' '}
                <select name="location_id" defaultValue="">
                  <option value="">Whole organization</option>
                  {activeLocations.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name}
                    </option>
                  ))}
                </select>
              </label>
            </p>
          </ActionForm>
        </>
      ) : null}
    </main>
  );
}
