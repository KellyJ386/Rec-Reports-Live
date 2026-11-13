import { beforeEach, describe, expect, it, vi } from 'vitest';

type RpcCall = { name: string; args: Record<string, unknown> };
const calls: RpcCall[] = [];
const selects: string[] = [];
let rpcResult: { data: unknown; error: unknown } = { data: null, error: null };

vi.mock('@/lib/supabase/server', () => ({
  createClient: async () => ({
    rpc: async (name: string, args: Record<string, unknown>) => {
      calls.push({ name, args });
      return rpcResult;
    },
    from: () => ({
      select: (columns: string) => {
        selects.push(columns);
        const chain: Record<string, unknown> = {};
        const self = () => chain;
        for (const m of ['eq', 'is', 'or', 'order', 'in', 'not', 'gt', 'gte']) chain[m] = self;
        chain.range = async () => ({ data: [], error: null, count: 0 });
        chain.maybeSingle = async () => ({ data: null, error: null });
        return chain;
      },
    }),
  }),
}));

import {
  assignShift,
  applyTemplate,
  getShift,
  listScheduleShifts,
  listShiftOverrides,
  listSwapCandidates,
  positionShiftsMissingQualification,
  requestSwap,
  updateShift,
} from './service';

const ID = '11111111-1111-4111-8111-111111111111';
const ID2 = '22222222-2222-4222-8222-222222222222';

beforeEach(() => {
  calls.length = 0;
  selects.length = 0;
  rpcResult = { data: null, error: null };
});

describe('shift reads', () => {
  it('never ask for the override columns the database no longer grants', async () => {
    await getShift(ID, ID2);
    await listScheduleShifts(ID, ID2);
    expect(selects.length).toBeGreaterThan(0);
    for (const columns of selects) {
      expect(columns).not.toContain('override');
      expect(columns).not.toContain('uncovered_emitted_for');
      expect(columns).not.toContain('*');
    }
  });
});

describe('listShiftOverrides', () => {
  it('calls shift_overrides and returns its rows', async () => {
    const row = {
      shift_id: ID,
      override_kinds: ['time_off'],
      override_by_person_id: ID2,
      override_at: '2026-11-12T10:00:00Z',
    };
    rpcResult = { data: [row], error: null };
    const res = await listShiftOverrides(ID2);
    expect(calls[0]).toEqual({ name: 'shift_overrides', args: { p_schedule_id: ID2 } });
    expect(res).toEqual({ ok: true, data: [row] });
  });
  it('shows nothing when the database refuses with 42501', async () => {
    rpcResult = { data: null, error: { code: '42501', message: 'not allowed' } };
    expect(await listShiftOverrides(ID)).toEqual({ ok: true, data: [] });
  });
  it('reports other failures', async () => {
    rpcResult = { data: null, error: { code: 'XX000', message: 'boom' } };
    expect((await listShiftOverrides(ID)).ok).toBe(false);
  });
});

describe('swap candidates and the qualification check', () => {
  it('reads swap_candidates for the shift', async () => {
    rpcResult = { data: [{ person_id: ID2, display_name: 'Ana Lopez' }], error: null };
    const res = await listSwapCandidates(ID);
    expect(calls[0]).toEqual({ name: 'swap_candidates', args: { p_shift_id: ID } });
    expect(res).toEqual({ ok: true, data: [{ person_id: ID2, display_name: 'Ana Lopez' }] });
  });
  it('counts upcoming shifts missing a qualification', async () => {
    rpcResult = { data: 4, error: null };
    expect(await positionShiftsMissingQualification(ID)).toEqual({ ok: true, data: 4 });
    expect(calls[0]?.name).toBe('position_shifts_missing_qualification');
  });
  it('sends a counter shift with a swap', async () => {
    rpcResult = { data: ID, error: null };
    await requestSwap({ shift_id: ID, to_person_id: ID2, counter_shift_id: ID2, note: null });
    expect(calls[0]?.args.p_counter_shift_id).toBe(ID2);
  });
});

describe('shift changes', () => {
  it('sends an empty note to clear it and null to keep it', async () => {
    await updateShift({ shift_id: ID, notes: '' });
    await updateShift({ shift_id: ID });
    expect(calls[0]?.args.p_notes).toBe('');
    expect(calls[1]?.args.p_notes).toBeNull();
  });
  it('carries the rule of a refused assignment', async () => {
    rpcResult = {
      data: null,
      error: {
        code: '23514',
        message: 'that person has approved time off then',
        details: 'time_off',
      },
    };
    const res = await assignShift({ shift_id: ID, person_id: ID2 });
    expect(res).toMatchObject({ ok: false, rule: 'time_off' });
  });
  it('returns template rows with shift_id null and the item', async () => {
    rpcResult = {
      data: [{ shift_id: null, assigned_person_id: null, refused: 'time_change', item_id: ID }],
      error: null,
    };
    const res = await applyTemplate({ schedule_id: ID, template_id: ID2 });
    expect(res.ok && res.data[0]?.shift_id).toBeNull();
    expect(res.ok && res.data[0]?.item_id).toBe(ID);
  });
});
