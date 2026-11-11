import Link from 'next/link';
import { ActionForm } from '@/experiences/admin/action-form';
import { getLocationsWithPermission, requireAdminArea } from '@/experiences/admin/access';
import { createWorkflowRuleAction } from '@/experiences/admin/actions/workflow-rules';
import { ErrorMessage } from '@/experiences/admin/ui';
import { ScopeSelect, WorkflowRuleFields } from '@/experiences/admin/workflow-fields';
import { listAllLocations } from '@/domains/organizations';
import { listTemplateChoices } from '@/domains/workflows';

export const metadata = { title: 'New workflow rule | Rec Reports' };

export default async function NewWorkflowRulePage() {
  const { orgId } = await requireAdminArea('canTasks');
  const [places, templates, locations] = await Promise.all([
    getLocationsWithPermission(orgId, 'tasks', 'admin'),
    listTemplateChoices(orgId),
    listAllLocations(orgId, { includeArchived: true }),
  ]);
  if (!places.ok) {
    return (
      <main>
        <h1>New workflow rule</h1>
        <ErrorMessage message={places.message} />
      </main>
    );
  }
  const usable = templates.ok ? templates.data.filter((t) => t.archived_at === null) : [];

  return (
    <main>
      <h1>New workflow rule</h1>
      <p>
        <Link href="/app/admin/workflow-rules">Back to workflow rules</Link>
      </p>
      <p>
        A new rule starts switched off. After you save it, open it and switch it on when you are
        ready for it to make tasks.
      </p>
      {templates.ok && usable.length === 0 ? (
        <p>
          You need a task template first. <Link href="/app/admin/task-templates/new">Make one</Link>
          .
        </p>
      ) : (
        <ActionForm action={createWorkflowRuleAction} submitLabel="Save rule (switched off)">
          <ScopeSelect allowAll={places.orgWide} locations={places.data} />
          <WorkflowRuleFields
            templates={usable}
            locationNames={new Map(locations.ok ? locations.data.map((l) => [l.id, l.name]) : [])}
            conditionRows={[]}
          />
          <p>
            A rule for one location can only use templates for all locations or for that same
            location.
          </p>
        </ActionForm>
      )}
    </main>
  );
}
