import { describe, expect, it } from 'vitest';
import {
  locationCreateSchema,
  locationUpdateSchema,
  organizationSettingsUpdateSchema,
  organizationUpdateSchema,
} from './schemas';

const ORG = '00000000-0000-4000-8000-000000000001';

describe('locationCreateSchema', () => {
  const valid = {
    organization_id: ORG,
    name: '  Lakeside Community Center ',
    timezone: 'America/New_York',
  };

  it('accepts a valid location and trims the name', () => {
    const out = locationCreateSchema.parse(valid);
    expect(out.name).toBe('Lakeside Community Center');
  });

  it('accepts UTC as a timezone', () => {
    expect(locationCreateSchema.safeParse({ ...valid, timezone: 'UTC' }).success).toBe(true);
  });

  it('rejects a blank name', () => {
    expect(locationCreateSchema.safeParse({ ...valid, name: '   ' }).success).toBe(false);
  });

  it('rejects legacy or POSIX timezone names', () => {
    expect(locationCreateSchema.safeParse({ ...valid, timezone: 'EST' }).success).toBe(false);
    expect(locationCreateSchema.safeParse({ ...valid, timezone: 'UTC+5' }).success).toBe(false);
  });

  it('rejects an unknown timezone', () => {
    expect(locationCreateSchema.safeParse({ ...valid, timezone: 'America/Atlantis' }).success).toBe(
      false,
    );
  });

  it('rejects a code with spaces', () => {
    expect(locationCreateSchema.safeParse({ ...valid, code: 'LAKE 1' }).success).toBe(false);
  });

  it('rejects fields a tenant may not set (id, created_at)', () => {
    expect(locationCreateSchema.safeParse({ ...valid, id: ORG }).success).toBe(false);
    expect(
      locationCreateSchema.safeParse({ ...valid, created_at: '2027-01-01T00:00:00Z' }).success,
    ).toBe(false);
  });
});

describe('locationUpdateSchema', () => {
  it('accepts a partial update', () => {
    expect(locationUpdateSchema.safeParse({ phone: '555-0100' }).success).toBe(true);
  });

  it('rejects an empty update', () => {
    expect(locationUpdateSchema.safeParse({}).success).toBe(false);
  });

  it('rejects organization_id on update', () => {
    expect(locationUpdateSchema.safeParse({ organization_id: ORG, name: 'X' }).success).toBe(false);
  });
});

describe('organizationUpdateSchema', () => {
  it('allows only name', () => {
    expect(organizationUpdateSchema.safeParse({ name: 'Lakeside Parks (Mock)' }).success).toBe(
      true,
    );
    expect(organizationUpdateSchema.safeParse({ slug: 'other' }).success).toBe(false);
  });
});

describe('organizationSettingsUpdateSchema', () => {
  it('accepts a valid week start and timezone', () => {
    expect(
      organizationSettingsUpdateSchema.safeParse({
        week_starts_on: 1,
        default_timezone: 'America/Denver',
      }).success,
    ).toBe(true);
  });

  it('rejects week_starts_on outside 0-6', () => {
    expect(organizationSettingsUpdateSchema.safeParse({ week_starts_on: 7 }).success).toBe(false);
  });

  it('rejects a non-object settings value through the record check', () => {
    expect(organizationSettingsUpdateSchema.safeParse({ settings: 'nope' }).success).toBe(false);
  });
});
