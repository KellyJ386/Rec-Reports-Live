import { beforeEach, describe, expect, it, vi } from 'vitest';

const calls: { name: string; args: Record<string, unknown> }[] = [];
let error: unknown = null;
const writes: string[] = [];

vi.mock('@/lib/supabase/server', () => ({
  createClient: async () => ({
    rpc: async (name: string, args: Record<string, unknown>) => {
      calls.push({ name, args });
      return { data: null, error };
    },
    from: () => ({
      update: () => {
        writes.push('update');
        return {};
      },
    }),
  }),
}));

import { updateStaffingSwitches } from './service';

const ORG = '11111111-1111-4111-8111-111111111111';

beforeEach(() => {
  calls.length = 0;
  writes.length = 0;
  error = null;
});

describe('updateStaffingSwitches', () => {
  it('calls set_staffing_switches and never writes the settings object', async () => {
    const res = await updateStaffingSwitches(ORG, {
      auto_approve_swaps: true,
      first_come_open_shifts: false,
    });
    expect(res.ok).toBe(true);
    expect(calls).toEqual([
      {
        name: 'set_staffing_switches',
        args: {
          p_organization_id: ORG,
          p_auto_approve_swaps: true,
          p_first_come_open_shifts: false,
        },
      },
    ]);
    expect(writes).toEqual([]);
  });
  it('maps a refusal to a plain message', async () => {
    error = { code: '42501', message: 'not allowed' };
    const res = await updateStaffingSwitches(ORG, {
      auto_approve_swaps: false,
      first_come_open_shifts: false,
    });
    expect(res.ok).toBe(false);
  });
});
