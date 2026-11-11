import Link from 'next/link';
import { ActionForm } from '@/experiences/admin/action-form';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import {
  markAllNotificationsReadAction,
  markNotificationReadAction,
  removeDeviceAction,
  saveChannelSettingsAction,
  saveDeviceAction,
} from '@/experiences/employee/actions/notifications';
import { PushToggle } from '@/experiences/employee/push-toggle';
import { StaffNav } from '@/experiences/employee/ui';
import { formatInZone } from '@/lib/time';
import { parsePage } from '@/lib/paging';
import {
  countPushDevices,
  getChannelSettings,
  listNotifications,
  safeLinkPath,
  urgencyFlag,
} from '@/domains/communications';
import { getOrganizationSettings } from '@/domains/organizations';

export const metadata = { title: 'Notifications | Rec Reports' };

export default async function NotificationsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, personId, access } = await requireStaffArea();
  const page = parsePage((await searchParams).page);
  // Read on the server and handed to the one client component. Unset means push is not set up.
  const vapidKey = process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY?.trim() ?? '';

  if (!personId) {
    return (
      <main>
        <h1>Notifications</h1>
        <StaffNav access={access} />
        <p>
          You do not have a staff profile in this organization, so you have no notifications here.
        </p>
      </main>
    );
  }

  const [res, settings, channels, devices] = await Promise.all([
    listNotifications(orgId, personId, page),
    getOrganizationSettings(orgId),
    getChannelSettings(orgId, personId),
    countPushDevices(orgId, personId),
  ]);
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  const rows = res.ok ? res.data.rows : [];
  const unread = rows.some((n) => n.read_at === null);

  return (
    <main>
      <h1>Notifications</h1>
      <StaffNav access={access} />
      <p>Only you can see your notifications. Times are in {tz}.</p>

      {!res.ok ? <ErrorMessage message={res.message} /> : null}
      {res.ok && rows.length === 0 ? <p>You have no notifications.</p> : null}
      {unread ? (
        <ActionForm action={markAllNotificationsReadAction} submitLabel="Mark all as read" />
      ) : null}
      <ul>
        {rows.map((n) => {
          const link = safeLinkPath(n.link_path);
          return (
            <li key={n.id}>
              <p>
                {n.read_at ? '' : 'NEW: '}
                {urgencyFlag(n.urgency)}
                {link ? <Link href={link}>{n.title}</Link> : n.title}
              </p>
              {n.body ? <p>{n.body}</p> : null}
              <p>{formatInZone(n.created_at, tz)}</p>
              {n.read_at ? null : (
                <ActionForm action={markNotificationReadAction} submitLabel="Mark as read">
                  <input type="hidden" name="notification_id" value={n.id} />
                </ActionForm>
              )}
            </li>
          );
        })}
      </ul>
      {res.ok ? (
        <Pager
          path="/app/notifications"
          page={res.data.page}
          total={res.data.total}
          pageSize={res.data.pageSize}
        />
      ) : null}

      <h2>Notification settings</h2>
      <p>
        Notifications always show here. You can choose whether you also get them by email or on your
        phone. Critical notices are always sent, whatever you choose.
      </p>
      {!channels.ok ? <ErrorMessage message={channels.message} /> : null}
      {channels.ok ? (
        <ActionForm action={saveChannelSettingsAction} submitLabel="Save settings">
          <p>
            <label>
              <input
                type="checkbox"
                name="email"
                value="yes"
                defaultChecked={channels.data.email}
              />{' '}
              Send me notifications by email
            </label>
          </p>
          <p>
            <label>
              <input type="checkbox" name="push" value="yes" defaultChecked={channels.data.push} />{' '}
              Send me notifications on my devices
            </label>
          </p>
        </ActionForm>
      ) : null}

      <h2>This device</h2>
      {devices.ok ? (
        <p>
          {devices.data === 0
            ? 'No device is set up for notifications yet.'
            : `${devices.data} ${devices.data === 1 ? 'device is' : 'devices are'} set up for notifications.`}
        </p>
      ) : null}
      {vapidKey === '' ? (
        <p>Device notifications are not set up yet.</p>
      ) : (
        <PushToggle
          vapidPublicKey={vapidKey}
          knownDevices={devices.ok ? devices.data : 0}
          save={saveDeviceAction}
          remove={removeDeviceAction}
        />
      )}
    </main>
  );
}
