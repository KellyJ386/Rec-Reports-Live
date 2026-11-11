// Plain form fields shared by create and edit screens. Server components: no state.
import { listTimeZones } from '@/lib/time';
import type { Location } from '@/domains/organizations';
import type { Person } from '@/domains/identity';

export function TimeZoneSelect({
  name,
  defaultValue,
  label,
}: {
  name: string;
  defaultValue: string;
  label: string;
}) {
  const zones = listTimeZones();
  const options = zones.includes(defaultValue) ? zones : [defaultValue, ...zones];
  return (
    <p>
      <label>
        {label}{' '}
        <select name={name} defaultValue={defaultValue} required>
          {options.map((z) => (
            <option key={z} value={z}>
              {z}
            </option>
          ))}
        </select>
      </label>
    </p>
  );
}

export function LocationFields({
  location,
  defaultTimezone,
}: {
  location?: Location;
  defaultTimezone: string;
}) {
  return (
    <>
      <p>
        <label>
          Name <input name="name" defaultValue={location?.name ?? ''} required maxLength={200} />
        </label>
      </p>
      <p>
        <label>
          Short code (optional){' '}
          <input name="code" defaultValue={location?.code ?? ''} maxLength={20} />
        </label>
      </p>
      <TimeZoneSelect
        name="timezone"
        label="Time zone"
        defaultValue={location?.timezone ?? defaultTimezone}
      />
      <p>
        <label>
          Address (optional){' '}
          <input name="address" defaultValue={location?.address ?? ''} maxLength={500} />
        </label>
      </p>
      <p>
        <label>
          Phone (optional){' '}
          <input name="phone" type="tel" defaultValue={location?.phone ?? ''} maxLength={40} />
        </label>
      </p>
    </>
  );
}

export function PersonFields({ person }: { person?: Person }) {
  return (
    <>
      <p>
        <label>
          First name{' '}
          <input
            name="first_name"
            defaultValue={person?.first_name ?? ''}
            required
            maxLength={100}
          />
        </label>
      </p>
      <p>
        <label>
          Last name{' '}
          <input name="last_name" defaultValue={person?.last_name ?? ''} required maxLength={100} />
        </label>
      </p>
      <p>
        <label>
          Preferred name (optional){' '}
          <input
            name="preferred_name"
            defaultValue={person?.preferred_name ?? ''}
            maxLength={100}
          />
        </label>
      </p>
      <p>
        <label>
          Email (optional){' '}
          <input name="email" type="email" defaultValue={person?.email ?? ''} maxLength={320} />
        </label>
      </p>
      <p>
        <label>
          Phone (optional){' '}
          <input name="phone" type="tel" defaultValue={person?.phone ?? ''} maxLength={40} />
        </label>
      </p>
      <p>
        <label>
          Employee number (optional){' '}
          <input
            name="employee_number"
            defaultValue={person?.employee_number ?? ''}
            maxLength={50}
          />
        </label>
      </p>
    </>
  );
}
