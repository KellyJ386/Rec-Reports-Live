import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { updateSettingsAction } from '@/experiences/admin/actions/settings';
import { TimeZoneSelect } from '@/experiences/admin/fields';
import { ErrorMessage } from '@/experiences/admin/ui';
import { WEEK_START_OPTIONS } from '@/lib/time';
import { getOrganization, getOrganizationSettings } from '@/domains/organizations';

export default async function SettingsPage() {
  const { orgId } = await requireAdminArea('isOrgAdmin');
  const [org, settings] = await Promise.all([
    getOrganization(orgId),
    getOrganizationSettings(orgId),
  ]);
  if (!org.ok) return <ErrorMessage message={org.message} />;
  if (!settings.ok) return <ErrorMessage message={settings.message} />;
  if (!org.data || !settings.data) return <ErrorMessage message="Settings could not be found." />;

  return (
    <main>
      <h1>Organization settings</h1>
      <ActionForm action={updateSettingsAction} submitLabel="Save">
        <p>
          <label>
            Organization name{' '}
            <input name="name" defaultValue={org.data.name} required maxLength={200} />
          </label>
        </p>
        <TimeZoneSelect
          name="default_timezone"
          label="Default time zone (used for new locations)"
          defaultValue={settings.data.default_timezone}
        />
        <p>
          <label>
            Week starts on{' '}
            <select name="week_starts_on" defaultValue={String(settings.data.week_starts_on)}>
              {WEEK_START_OPTIONS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </label>
        </p>
      </ActionForm>
    </main>
  );
}
