import { describe, expect, it } from 'vitest';
import {
  spaceClosureCreateSchema,
  spaceCreateSchema,
  spaceHourCreateSchema,
  spaceHourUpdateSchema,
  spaceKindCreateSchema,
  spaceUpdateSchema,
} from './schemas';

const ORG = '00000000-0000-4000-8000-000000000001';
const LOC = '00000000-0000-4000-8000-000000000002';
const SPACE = '00000000-0000-4000-8000-000000000003';

describe('spaceKindCreateSchema', () => {
  it('accepts a lowercase key', () => {
    expect(
      spaceKindCreateSchema.safeParse({ organization_id: ORG, key: 'pool', name: 'Pool' }).success,
    ).toBe(true);
  });

  it('rejects a key with uppercase letters or a leading digit', () => {
    expect(
      spaceKindCreateSchema.safeParse({ organization_id: ORG, key: 'Pool', name: 'Pool' }).success,
    ).toBe(false);
    expect(
      spaceKindCreateSchema.safeParse({ organization_id: ORG, key: '1pool', name: 'Pool' }).success,
    ).toBe(false);
  });
});

describe('spaceCreateSchema', () => {
  const valid = {
    organization_id: ORG,
    location_id: LOC,
    space_kind_id: SPACE,
    name: 'Lap pool',
    capacity: 40,
  };

  it('accepts a valid space', () => {
    expect(spaceCreateSchema.safeParse(valid).success).toBe(true);
  });

  it('rejects a non-uuid location', () => {
    expect(spaceCreateSchema.safeParse({ ...valid, location_id: 'lakeside' }).success).toBe(false);
  });

  it('rejects negative capacity', () => {
    expect(spaceCreateSchema.safeParse({ ...valid, capacity: -1 }).success).toBe(false);
  });

  it('rejects archived_at on create', () => {
    expect(
      spaceCreateSchema.safeParse({ ...valid, archived_at: '2027-01-01T00:00:00Z' }).success,
    ).toBe(false);
  });
});

describe('spaceUpdateSchema', () => {
  it('rejects location_id (immutable) and organization_id on update', () => {
    expect(spaceUpdateSchema.safeParse({ location_id: LOC }).success).toBe(false);
    expect(spaceUpdateSchema.safeParse({ organization_id: ORG, name: 'X' }).success).toBe(false);
  });

  it('accepts archiving a space', () => {
    expect(spaceUpdateSchema.safeParse({ archived_at: '2027-05-01T00:00:00Z' }).success).toBe(true);
  });
});

describe('spaceHourCreateSchema', () => {
  const base = {
    organization_id: ORG,
    location_id: LOC,
    space_id: SPACE,
    day_of_week: 1,
    opens_at: '06:00',
    closes_at: '21:00',
  };

  it('accepts a normal day', () => {
    expect(spaceHourCreateSchema.safeParse(base).success).toBe(true);
  });

  it('accepts closing at 24:00', () => {
    expect(spaceHourCreateSchema.safeParse({ ...base, closes_at: '24:00' }).success).toBe(true);
  });

  it('rejects day 0 and day 8 (ISO days are 1-7)', () => {
    expect(spaceHourCreateSchema.safeParse({ ...base, day_of_week: 0 }).success).toBe(false);
    expect(spaceHourCreateSchema.safeParse({ ...base, day_of_week: 8 }).success).toBe(false);
  });

  it('rejects closing time not after opening time', () => {
    expect(
      spaceHourCreateSchema.safeParse({ ...base, opens_at: '21:00', closes_at: '06:00' }).success,
    ).toBe(false);
    expect(
      spaceHourCreateSchema.safeParse({ ...base, opens_at: '06:00', closes_at: '06:00' }).success,
    ).toBe(false);
  });

  it('rejects 24:00 as an opening time', () => {
    expect(spaceHourCreateSchema.safeParse({ ...base, opens_at: '24:00' }).success).toBe(false);
  });

  it('rejects an end date before the start date', () => {
    expect(
      spaceHourCreateSchema.safeParse({
        ...base,
        effective_from: '2027-06-01',
        effective_to: '2027-05-01',
      }).success,
    ).toBe(false);
  });
});

describe('spaceHourUpdateSchema', () => {
  it('rejects a partial update that makes closes_at before opens_at', () => {
    expect(spaceHourUpdateSchema.safeParse({ opens_at: '20:00', closes_at: '08:00' }).success).toBe(
      false,
    );
  });

  it('rejects space_id on update (immutable)', () => {
    expect(spaceHourUpdateSchema.safeParse({ space_id: SPACE }).success).toBe(false);
  });
});

describe('spaceClosureCreateSchema', () => {
  const base = {
    organization_id: ORG,
    location_id: LOC,
    space_id: null,
    starts_at: '2027-07-04T00:00:00Z',
    ends_at: '2027-07-05T00:00:00Z',
    reason: 'Holiday closure',
  };

  it('accepts a whole-location closure (space_id null)', () => {
    expect(spaceClosureCreateSchema.safeParse(base).success).toBe(true);
  });

  it('rejects an end not after the start', () => {
    expect(spaceClosureCreateSchema.safeParse({ ...base, ends_at: base.starts_at }).success).toBe(
      false,
    );
  });

  it('rejects a timestamp without a timezone', () => {
    expect(
      spaceClosureCreateSchema.safeParse({ ...base, starts_at: '2027-07-04T00:00:00' }).success,
    ).toBe(false);
  });
});
