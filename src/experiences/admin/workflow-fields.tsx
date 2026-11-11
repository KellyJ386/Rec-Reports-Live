// Plain form fields for task templates, workflow rules and notices. Server components: no state.
import { utcToZonedLocal } from '@/lib/time';
import {
  ASSIGN_TO_OPTIONS,
  CLAUSE_OPS,
  CLAUSE_TYPES,
  EMPTY_CLAUSE,
  EVENT_TYPE_OPTIONS,
  FORM_CLAUSE_ROWS,
  MAX_CLAUSES,
  OFFSET_DIRECTIONS,
  OFFSET_UNITS,
  TASK_PRIORITIES,
  offsetToForm,
  priorityLabel,
  type ClauseInput,
  type TaskTemplate,
  type TemplateChoice,
} from '@/domains/workflows';
import {
  NOTICE_URGENCIES,
  urgencyLabel,
  type AudienceOptions,
  type Notice,
} from '@/domains/communications';
import { displayName, type JobTitle, type Person } from '@/domains/identity';
import type { Location } from '@/domains/organizations';

/** A person picker: the person already chosen (if any) plus the people a search found. */
export function PersonSelect({
  name,
  label,
  current,
  matches,
}: {
  name: string;
  label: string;
  current: { id: string; name: string } | null;
  matches: readonly Person[];
}) {
  const others = matches.filter((p) => p.id !== current?.id);
  return (
    <p>
      <label>
        {label}{' '}
        <select name={name} defaultValue={current?.id ?? ''}>
          <option value="">Choose a person</option>
          {current ? <option value={current.id}>{current.name}</option> : null}
          {others.map((p) => (
            <option key={p.id} value={p.id}>
              {displayName(p)}
            </option>
          ))}
        </select>
      </label>
    </p>
  );
}

export function TaskTemplateFields({
  template,
  titles,
  currentPerson,
  matches,
}: {
  template?: TaskTemplate;
  titles: readonly JobTitle[];
  currentPerson: { id: string; name: string } | null;
  matches: readonly Person[];
}) {
  const offset = offsetToForm(template?.due_offset_minutes ?? null);
  return (
    <>
      <p>
        <label>
          Task title{' '}
          <input name="title" defaultValue={template?.title ?? ''} required maxLength={200} />
        </label>
      </p>
      <p>
        <label>
          What to do (optional){' '}
          <textarea
            name="instructions"
            rows={4}
            maxLength={4000}
            defaultValue={template?.instructions ?? ''}
          />
        </label>
      </p>
      <p>
        <label>
          Priority{' '}
          <select name="default_priority" defaultValue={template?.default_priority ?? 'normal'}>
            {TASK_PRIORITIES.map((p) => (
              <option key={p} value={p}>
                {priorityLabel(p)}
              </option>
            ))}
          </select>
        </label>
      </p>
      <fieldset>
        <legend>When it is due (optional)</legend>
        <p>
          <label>
            Amount{' '}
            <input name="offset_amount" inputMode="numeric" defaultValue={offset.amount} size={6} />
          </label>{' '}
          <label>
            Unit{' '}
            <select name="offset_unit" defaultValue={offset.unit}>
              {OFFSET_UNITS.map((u) => (
                <option key={u.value} value={u.value}>
                  {u.label}
                </option>
              ))}
            </select>
          </label>{' '}
          <label>
            <select
              name="offset_direction"
              defaultValue={offset.direction}
              aria-label="Before or after"
            >
              {OFFSET_DIRECTIONS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </label>{' '}
          the time of the event (for example, the start of a booking). Leave the amount empty for no
          due time.
        </p>
      </fieldset>
      <fieldset>
        <legend>Who gets the task</legend>
        <p>
          <label>
            Give it to{' '}
            <select name="assign_to" defaultValue={template?.assign_to ?? 'none'}>
              {ASSIGN_TO_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            Job title (when giving it to a job title){' '}
            <select name="assign_job_title_id" defaultValue={template?.assign_job_title_id ?? ''}>
              <option value="">Choose a job title</option>
              {titles.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                  {t.archived_at ? ' (archived)' : ''}
                </option>
              ))}
            </select>
          </label>
        </p>
        <PersonSelect
          name="assign_person_id"
          label="Person (when giving it to one person)"
          current={currentPerson}
          matches={matches}
        />
      </fieldset>
    </>
  );
}

/** The condition editor: a few plain rows, each "field, is / is one of, value". */
export function ConditionEditor({ rows }: { rows: readonly ClauseInput[] }) {
  const shown = Math.min(MAX_CLAUSES, Math.max(FORM_CLAUSE_ROWS, rows.length + 1));
  return (
    <fieldset>
      <legend>Only when (optional)</legend>
      <p>
        Leave these empty to make a task every time the event happens. Each row narrows it: the
        event must match every row you fill in.
      </p>
      {Array.from({ length: shown }, (_, i) => {
        const row = rows[i] ?? EMPTY_CLAUSE;
        return (
          <p key={i}>
            <label>
              Field <input name={`c${i}_field`} defaultValue={row.field} maxLength={63} />
            </label>{' '}
            <label>
              <select
                name={`c${i}_op`}
                defaultValue={row.op}
                aria-label={`Row ${i + 1} comparison`}
              >
                {CLAUSE_OPS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>{' '}
            <label>
              Value <input name={`c${i}_value`} defaultValue={row.value} />
            </label>{' '}
            <label>
              Kind of value{' '}
              <select name={`c${i}_type`} defaultValue={row.type}>
                {CLAUSE_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </label>
          </p>
        );
      })}
    </fieldset>
  );
}

export function WorkflowRuleFields({
  rule,
  templates,
  locationNames,
  conditionRows,
}: {
  rule?: { name: string; event_type: string; task_template_id: string };
  templates: readonly TemplateChoice[];
  locationNames: ReadonlyMap<string, string>;
  /** null = the stored condition cannot be shown here and stays as it is. */
  conditionRows: readonly ClauseInput[] | null;
}) {
  return (
    <>
      <p>
        <label>
          Rule name <input name="name" defaultValue={rule?.name ?? ''} required maxLength={200} />
        </label>
      </p>
      <p>
        <label>
          When this happens{' '}
          <select name="event_type" defaultValue={rule?.event_type ?? ''} required>
            <option value="" disabled>
              Choose what happens
            </option>
            {EVENT_TYPE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      </p>
      {conditionRows === null ? (
        <>
          <input type="hidden" name="condition_kept" value="yes" />
          <p>
            This rule has a condition that cannot be shown here. It is kept as it is when you save.
          </p>
        </>
      ) : (
        <ConditionEditor rows={conditionRows} />
      )}
      <p>
        <label>
          Make this task{' '}
          <select name="task_template_id" defaultValue={rule?.task_template_id ?? ''} required>
            <option value="" disabled>
              Choose a task template
            </option>
            {templates.map((t) => (
              <option key={t.id} value={t.id}>
                {t.title} (
                {t.location_id
                  ? (locationNames.get(t.location_id) ?? 'one location')
                  : 'all locations'}
                ){t.archived_at ? ' (archived)' : ''}
              </option>
            ))}
          </select>
        </label>
      </p>
    </>
  );
}

/** Where a new template or rule applies: every location, or one the person manages. */
export function ScopeSelect({
  allowAll,
  locations,
}: {
  allowAll: boolean;
  locations: readonly Location[];
}) {
  return (
    <p>
      <label>
        Where it applies{' '}
        <select
          name="location_id"
          defaultValue={allowAll ? '' : (locations[0]?.id ?? '')}
          required={!allowAll}
        >
          {allowAll ? <option value="">All locations</option> : null}
          {locations.map((l) => (
            <option key={l.id} value={l.id}>
              {l.name} only
            </option>
          ))}
        </select>
      </label>
    </p>
  );
}

export function NoticeFields({ notice, timezone }: { notice?: Notice; timezone: string }) {
  return (
    <>
      <p>
        <label>
          Title <input name="title" defaultValue={notice?.title ?? ''} required maxLength={200} />
        </label>
      </p>
      <p>
        <label>
          Message{' '}
          <textarea
            name="body"
            rows={8}
            required
            maxLength={5000}
            defaultValue={notice?.body ?? ''}
          />
        </label>
      </p>
      <p>
        <label>
          How urgent{' '}
          <select name="urgency" defaultValue={notice?.urgency ?? 'normal'}>
            {NOTICE_URGENCIES.map((u) => (
              <option key={u} value={u}>
                {urgencyLabel(u)}
              </option>
            ))}
          </select>
        </label>
      </p>
      <p>
        <label>
          <input
            type="checkbox"
            name="requires_acknowledgment"
            value="yes"
            defaultChecked={notice?.requires_acknowledgment ?? false}
          />{' '}
          People must confirm they have read it
        </label>
      </p>
      <p>
        <label>
          Stop showing it on (optional), in {timezone}{' '}
          <input
            type="datetime-local"
            name="expires_at"
            defaultValue={utcToZonedLocal(notice?.expires_at, timezone)}
          />
        </label>
      </p>
    </>
  );
}

export function AudienceFields({
  options,
  titles,
}: {
  options: AudienceOptions;
  titles: readonly JobTitle[];
}) {
  return (
    <fieldset>
      <legend>Who it is for</legend>
      {options.allowOrganization ? (
        <p>
          <label>
            <input type="radio" name="scope" value="organization" defaultChecked /> The whole
            organization
          </label>
        </p>
      ) : null}
      <p>
        <label>
          <input
            type="radio"
            name="scope"
            value="locations"
            defaultChecked={!options.allowOrganization}
          />{' '}
          {options.allowMultipleLocations ? 'These locations' : 'This location'}
        </label>
      </p>
      <ul>
        {options.locations.map((l) => (
          <li key={l.id}>
            <label>
              <input
                type={options.allowMultipleLocations ? 'checkbox' : 'radio'}
                name="location_ids"
                value={l.id}
              />{' '}
              {l.name}
            </label>
          </li>
        ))}
      </ul>
      <p>Only people with these job titles (tick none to send to everyone there):</p>
      <ul>
        {titles.map((t) => (
          <li key={t.id}>
            <label>
              <input type="checkbox" name="job_title_ids" value={t.id} /> {t.name}
            </label>
          </li>
        ))}
      </ul>
    </fieldset>
  );
}
