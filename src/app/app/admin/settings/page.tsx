import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { updateSettingsAction } from '@/experiences/admin/actions/settings';
import { updateStaffingSwitchesAction } from '@/experiences/admin/actions/schedule';
import { TimeZoneSelect } from '@/experiences/admin/fields';
import { ErrorMessage } from '@/experiences/admin/ui';
import { WEEK_START_OPTIONS } from '@/lib/time';
import {
  getOrganization,
  getOrganizationSettings,
  getStaffingSwitches,
} from '@/domains/organizations';

export default async function SettingsPage() {
  const { orgId } = await requireAdminArea('isOrgAdmin');
  const [org, settings, switches] = await Promise.all([
    getOrganization(orgId),
    getOrganizationSettings(orgId),
    getStaffingSwitches(orgId),
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
      <h2>Staff scheduling</h2>
      {!switches.ok ? (
        <ErrorMessage message={switches.message} />
      ) : (
        <ActionForm action={updateStaffingSwitchesAction} submitLabel="Save">
          <p>
            <label>
              <input
                type="checkbox"
                name="auto_approve_swaps"
                value="yes"
                defaultChecked={switches.data.auto_approve_swaps}
              />{' '}
              Approve a plain swap without a manager once both people agree (a swap with a shift in
              return still goes to a manager)
            </label>
          </p>
          <p>
            <label>
              <input
                type="checkbox"
                name="first_come_open_shifts"
                value="yes"
                defaultChecked={switches.data.first_come_open_shifts}
              />{' '}
              Give an open shift to the first person who asks, if they can work it
            </label>
          </p>
        </ActionForm>
      )}
    </main>
  );
}
