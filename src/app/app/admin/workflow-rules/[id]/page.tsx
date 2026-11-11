import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { requireAdminArea } from '@/experiences/admin/access';
import {
  archiveWorkflowRuleAction,
  disableWorkflowRuleAction,
  enableWorkflowRuleAction,
  restoreWorkflowRuleAction,
  updateWorkflowRuleAction,
} from '@/experiences/admin/actions/workflow-rules';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { guidParam } from '@/experiences/admin/page-params';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { WorkflowRuleFields } from '@/experiences/admin/workflow-fields';
import { listAllLocations } from '@/domains/organizations';
import {
  conditionToForm,
  eventTypeLabel,
  getWorkflowRule,
  listTemplateChoices,
} from '@/domains/workflows';

export const metadata = { title: 'Workflow rule | Rec Reports' };

export default async function WorkflowRulePage({ params }: { params: Promise<{ id: string }> }) {
  const { orgId } = await requireAdminArea('canTasks');
  const id = guidParam((await params).id);
  const res = await getWorkflowRule(orgId, id);
  if (!res.ok) {
    return (
      <main>
        <h1>Workflow rule</h1>
        <ErrorMessage message={res.message} />
      </main>
    );
  }
  if (!res.data) notFound();
  const rule = res.data;

  const [templates, locations] = await Promise.all([
    listTemplateChoices(orgId),
    listAllLocations(orgId, { includeArchived: true }),
  ]);
  const locationNames = new Map(locations.ok ? locations.data.map((l) => [l.id, l.name]) : []);
  // Active templates, plus the one this rule already uses even if it has since been archived.
  const choices = templates.ok
    ? templates.data.filter((t) => t.archived_at === null || t.id === rule.task_template_id)
    : [];
  const where = rule.location_id
    ? (locationNames.get(rule.location_id) ?? 'One location') + ' only'
    : 'All locations';

  return (
    <main>
      <h1>
        {rule.name}
        <ArchivedMark archivedAt={rule.archived_at} />
      </h1>
      <p>
        <Link href="/app/admin/workflow-rules">Back to workflow rules</Link>
      </p>
      <p>
        State: <strong>{rule.enabled ? 'Switched on' : 'Switched off'}</strong>. When:{' '}
        {eventTypeLabel(rule.event_type)}. Where it applies: {where} (this cannot be changed after
        the rule is made).
      </p>

      {rule.archived_at ? null : rule.enabled ? (
        <>
          <p>This rule makes tasks automatically.</p>
          <ActionForm action={disableWorkflowRuleAction} submitLabel="Switch off">
            <input type="hidden" name="id" value={rule.id} />
          </ActionForm>
        </>
      ) : (
        <>
          <p>This rule is switched off, so it does nothing yet. Rules always start switched off.</p>
          <ActionForm action={enableWorkflowRuleAction} submitLabel="Switch on">
            <input type="hidden" name="id" value={rule.id} />
          </ActionForm>
        </>
      )}

      <h2>Change this rule</h2>
      <ActionForm action={updateWorkflowRuleAction} submitLabel="Save changes">
        <input type="hidden" name="id" value={rule.id} />
        <WorkflowRuleFields
          rule={rule}
          templates={choices}
          locationNames={locationNames}
          conditionRows={conditionToForm(rule.condition)}
        />
      </ActionForm>

      <h2>{rule.archived_at ? 'Restore' : 'Archive'}</h2>
      {rule.archived_at ? (
        <ActionForm action={restoreWorkflowRuleAction} submitLabel="Restore">
          <input type="hidden" name="id" value={rule.id} />
        </ActionForm>
      ) : (
        <ConfirmAction
          action={archiveWorkflowRuleAction}
          label="Archive"
          question="Yes, archive this rule. It will be switched off."
          fields={{ id: rule.id }}
        />
      )}
    </main>
  );
}
