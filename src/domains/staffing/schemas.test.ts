import { describe, expect, it } from 'vitest';
import {
  availabilitySchema,
  personQualificationSchema,
  positionSaveSchema,
  shiftAssignSchema,
  shiftCreateSchema,
  shiftUpdateSchema,
  swapRequestSchema,
  templateItemSchema,
  timeOffRequestSchema,
} from './schemas';

const ID = '11111111-1111-4111-8111-111111111111';
const ID2 = '22222222-2222-4222-8222-222222222222';
const ok = (s: { safeParse: (v: unknown) => { success: boolean } }, v: unknown) =>
  s.safeParse(v).success;

describe('shift schemas', () => {
  const shift = {
    schedule_id: ID,
    position_id: ID2,
    starts_at: '2026-11-16T14:00:00Z',
    ends_at: '2026-11-16T22:00:00Z',
  };
  it('accepts a normal shift and turns blank notes into null', () => {
    expect(ok(shiftCreateSchema, shift)).toBe(true);
    const parsed = shiftCreateSchema.parse({ ...shift, notes: '   ', override: true });
    expect(parsed.notes).toBeNull();
  });
  it('rejects an end before the start, more than 24 hours, and unknown keys', () => {
    expect(ok(shiftCreateSchema, { ...shift, ends_at: '2026-11-16T13:00:00Z' })).toBe(false);
    expect(ok(shiftCreateSchema, { ...shift, ends_at: '2026-11-17T14:00:01Z' })).toBe(false);
    expect(ok(shiftCreateSchema, { ...shift, ends_at: '2026-11-17T14:00:00Z' })).toBe(true);
    expect(ok(shiftCreateSchema, { ...shift, status: 'cancelled' })).toBe(false);
    expect(ok(shiftCreateSchema, { ...shift, notes: 'x'.repeat(1001) })).toBe(false);
  });
  it('lets an update change only some fields, and checks the span when both times are given', () => {
    expect(ok(shiftUpdateSchema, { shift_id: ID, notes: 'x' })).toBe(true);
    expect(
      ok(shiftUpdateSchema, {
        shift_id: ID,
        starts_at: '2026-11-16T14:00:00Z',
        ends_at: '2026-11-16T10:00:00Z',
      }),
    ).toBe(false);
  });
  it('assign takes a person or null (open the shift)', () => {
    expect(ok(shiftAssignSchema, { shift_id: ID, person_id: null })).toBe(true);
    expect(ok(shiftAssignSchema, { shift_id: ID, person_id: 'nope' })).toBe(false);
  });
});

describe('other schemas', () => {
  it('position: at most 20 qualifications, a name of 1 to 100', () => {
    const base = { organization_id: ID, location_id: null, name: 'Lifeguard' };
    expect(ok(positionSaveSchema, base)).toBe(true);
    expect(ok(positionSaveSchema, { ...base, name: ' ' })).toBe(false);
    expect(ok(positionSaveSchema, { ...base, name: 'x'.repeat(101) })).toBe(false);
    expect(ok(positionSaveSchema, { ...base, qualification_ids: Array(21).fill(ID) })).toBe(false);
  });
  it('person qualification: dates in order', () => {
    const base = { organization_id: ID, person_id: ID, qualification_id: ID2 };
    expect(
      ok(personQualificationSchema, { ...base, valid_from: null, expires_on: '2027-01-01' }),
    ).toBe(true);
    expect(
      ok(personQualificationSchema, {
        ...base,
        valid_from: '2027-02-01',
        expires_on: '2027-01-01',
      }),
    ).toBe(false);
  });
  it('template item: 15 minutes to 24 hours, day 0 to 6', () => {
    const base = {
      template_id: ID,
      position_id: ID2,
      day_offset: 0,
      start_time: '09:00',
      duration_minutes: 60,
    };
    expect(ok(templateItemSchema, base)).toBe(true);
    expect(ok(templateItemSchema, { ...base, duration_minutes: 14 })).toBe(false);
    expect(ok(templateItemSchema, { ...base, duration_minutes: 1441 })).toBe(false);
    expect(ok(templateItemSchema, { ...base, day_offset: 7 })).toBe(false);
    expect(ok(templateItemSchema, { ...base, start_time: '9am' })).toBe(false);
  });
  it('swap: needs the other person; note up to 500', () => {
    expect(ok(swapRequestSchema, { shift_id: ID, to_person_id: ID2 })).toBe(true);
    expect(ok(swapRequestSchema, { shift_id: ID })).toBe(false);
    expect(ok(swapRequestSchema, { shift_id: ID, to_person_id: ID2, note: 'x'.repeat(501) })).toBe(
      false,
    );
  });
  it('availability: end after start, 24:00 allowed, day 1 to 7', () => {
    const base = {
      organization_id: ID,
      day_of_week: 1,
      start_time: '09:00',
      end_time: '17:00',
      kind: 'available',
    };
    expect(ok(availabilitySchema, base)).toBe(true);
    expect(ok(availabilitySchema, { ...base, end_time: '24:00' })).toBe(true);
    expect(ok(availabilitySchema, { ...base, end_time: '08:00' })).toBe(false);
    expect(ok(availabilitySchema, { ...base, day_of_week: 8 })).toBe(false);
    expect(ok(availabilitySchema, { ...base, kind: 'maybe' })).toBe(false);
  });
  it('time off: last day not before the first, at most a year', () => {
    const base = { organization_id: ID, starts_on: '2026-12-01', ends_on: '2026-12-03' };
    expect(ok(timeOffRequestSchema, base)).toBe(true);
    expect(ok(timeOffRequestSchema, { ...base, ends_on: '2026-11-30' })).toBe(false);
    expect(ok(timeOffRequestSchema, { ...base, ends_on: '2028-01-01' })).toBe(false);
    expect(ok(timeOffRequestSchema, { ...base, reason: 'x'.repeat(501) })).toBe(false);
  });
});
