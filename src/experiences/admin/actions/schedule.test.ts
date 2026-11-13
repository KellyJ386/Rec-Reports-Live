import { beforeEach, describe, expect, it, vi } from 'vitest';

const ORG = '11111111-1111-4111-8111-111111111111';
const LOC = '22222222-2222-4222-8222-222222222222';
const SHIFT = '33333333-3333-4333-8333-333333333333';
const PERSON = '44444444-4444-4444-8444-444444444444';
const ME = '55555555-5555-4555-8555-555555555555';

const assignCalls: { person_id: string | null; override?: boolean }[] = [];
let assignScript: ((override: boolean) => unknown)[] = [];
let isAdmin = true;
let missingCount = 0;
let templateRows: unknown[] = [];

vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));
vi.mock('next/navigation', () => ({
  redirect: () => {
    throw new Error('redirect');
  },
}));
vi.mock('@/lib/auth', () => ({
  getActiveOrganization: async () => ({ organizationId: ORG, organizationName: 'Org' }),
  requireOrgMember: async () => ({ personId: ME }),
  requireAdmin: async () => ({ personId: ME }),
  requireModulePermission: async (_o: string, _l: string, _m: string, level: string) => {
    if (level === 'admin' && !isAdmin) throw new Error('denied');
    return { personId: ME };
  },
}));
vi.mock('@/experiences/schedule/lookups', () => ({
  loadScheduleLookups: async () => ({
    weekStartsOn: 0,
    locations: new Map(),
    positions: new Map([['pos', 'Lifeguard']]),
  }),
  loadNames: async () => ({ [PERSON]: 'Ana Lopez' }),
  nameOf: (names: Record<string, string>, id: string) => names[id] ?? 'Someone',
  zoneOf: () => 'America/Chicago',
}));
vi.mock('@/domains/organizations', () => ({
  getLocation: async () => ({ ok: true, data: { timezone: 'America/Chicago' } }),
  updateStaffingSwitches: async () => ({ ok: true, data: null }),
}));
vi.mock('@/domains/staffing', async () => {
  const actual = await vi.importActual<typeof import('@/domains/staffing')>('@/domains/staffing');
  return {
    ...actual,
    assignShift: async (input: { person_id: string | null; override?: boolean }) => {
      assignCalls.push({ person_id: input.person_id, override: input.override });
      const step = assignScript.shift();
      return step ? step(input.override === true) : { ok: true, data: null };
    },
    getShift: async () => ({
      ok: true,
      data: {
        id: SHIFT,
        location_id: LOC,
        position_id: 'pos',
        starts_at: '2026-11-20T15:00:00Z',
        ends_at: '2026-11-20T23:00:00Z',
      },
    }),
    positionShiftsMissingQualification: async () => ({ ok: true, data: missingCount }),
    savePosition: async () => ({ ok: true, data: ID_POSITION }),
    applyTemplate: async () => ({ ok: true, data: templateRows }),
  };
});

const ID_POSITION = '66666666-6666-4666-8666-666666666666';

import { applyTemplateAction, assignShiftAction, savePositionAction } from './schedule';

function form(values: Record<string, string>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(values)) f.set(k, v);
  return f;
}
const refuse = (rule: string) => () => ({
  ok: false,
  message: `refused: ${rule}`,
  rule,
});
const assignForm = (extra: Record<string, string> = {}) =>
  form({ location_id: LOC, shift_id: SHIFT, person_id: PERSON, ...extra });

beforeEach(() => {
  assignCalls.length = 0;
  assignScript = [];
  isAdmin = true;
  missingCount = 0;
  templateRows = [];
});

describe('assignShiftAction: the override offer', () => {
  it('answers with a server-built offer naming person, shift and rule, and does not override yet', async () => {
    assignScript = [refuse('time_off')];
    const res = await assignShiftAction({}, assignForm());
    expect(res.ok).toBe(false);
    expect(res.offer?.message).toContain('Ana Lopez');
    expect(res.offer?.message).toContain('Lifeguard');
    expect(res.offer?.message).toContain('approved time off');
    expect(res.offer?.fields).toMatchObject({
      shift_id: SHIFT,
      person_id: PERSON,
      location_id: LOC,
      rule: 'time_off',
    });
    expect(assignCalls).toEqual([{ person_id: PERSON, override: false }]);
  });

  it('overrides only after a second explicit submit, and only for the refusal still in force', async () => {
    assignScript = [refuse('qualification'), (o) => (o ? { ok: true, data: null } : refuse('x')())];
    const res = await assignShiftAction({}, assignForm({ override: 'yes', rule: 'qualification' }));
    expect(res.ok).toBe(true);
    expect(assignCalls.map((c) => c.override)).toEqual([false, true]);
  });

  it('refuses to override a rule other than the one that was shown', async () => {
    assignScript = [refuse('time_off')];
    const res = await assignShiftAction({}, assignForm({ override: 'yes', rule: 'qualification' }));
    expect(res.ok).toBe(false);
    expect(assignCalls).toEqual([{ person_id: PERSON, override: false }]);
  });

  it('does not use anything from a link: a crafted override with no refusal just assigns normally', async () => {
    const res = await assignShiftAction({}, assignForm({ override: 'yes', rule: 'time_off' }));
    expect(res.ok).toBe(true);
    expect(assignCalls).toEqual([{ person_id: PERSON, override: false }]);
  });

  it('never offers an override for an overlap or a person who cannot work there', async () => {
    for (const rule of ['overlap', 'not_member']) {
      assignScript = [refuse(rule)];
      const res = await assignShiftAction({}, assignForm());
      expect(res.ok).toBe(false);
      expect(res.offer).toBeUndefined();
    }
  });

  it('never offers an override to someone who is not a schedule admin', async () => {
    isAdmin = false;
    assignScript = [refuse('time_off')];
    const res = await assignShiftAction({}, assignForm());
    expect(res.offer).toBeUndefined();
  });

  it('does not offer an override when the person is the signed-in person', async () => {
    assignScript = [refuse('time_off')];
    const res = await assignShiftAction({}, assignForm({ person_id: ME }));
    expect(res.ok).toBe(false);
    expect(res.offer).toBeUndefined();
    expect(assignCalls).toHaveLength(1);
  });
});

describe('savePositionAction', () => {
  const pform = () => form({ location_id: '', name: 'Lifeguard' });
  it('says how many upcoming shifts now miss the qualification', async () => {
    missingCount = 3;
    const res = await savePositionAction({}, pform());
    expect(res.ok).toBe(true);
    expect(res.message).toContain('3 upcoming shifts have someone missing this qualification');
  });
  it('says nothing extra when no shift is affected', async () => {
    const res = await savePositionAction({}, pform());
    expect(res.message).toBe('Saved.');
  });
});

describe('applyTemplateAction', () => {
  it('explains time_change and position_unavailable rows that made no shift', async () => {
    templateRows = [
      { shift_id: 's1', assigned_person_id: PERSON, refused: null, item_id: 'i1' },
      { shift_id: 's2', assigned_person_id: null, refused: 'time_off', item_id: 'i2' },
      { shift_id: null, assigned_person_id: null, refused: 'time_change', item_id: 'i3' },
      { shift_id: null, assigned_person_id: null, refused: 'position_unavailable', item_id: 'i4' },
    ];
    const res = await applyTemplateAction(
      {},
      form({ location_id: LOC, schedule_id: SHIFT, template_id: PERSON }),
    );
    expect(res.ok).toBe(true);
    expect(res.message).toContain('Added 2 shifts.');
    expect(res.message).toContain('clock change');
    expect(res.message).toContain('archived');
    expect(res.message).toContain('approved time off');
  });
});
