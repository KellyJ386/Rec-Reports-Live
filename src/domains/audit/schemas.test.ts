import { describe, expect, it } from 'vitest';
import { auditLogFilterSchema } from './schemas';

const ORG = '00000000-0000-4000-8000-000000000001';

describe('auditLogFilterSchema', () => {
  it('applies a default limit of 50', () => {
    expect(auditLogFilterSchema.parse({ organization_id: ORG }).limit).toBe(50);
  });

  it('rejects a limit above 200', () => {
    expect(auditLogFilterSchema.safeParse({ organization_id: ORG, limit: 500 }).success).toBe(
      false,
    );
  });

  it('rejects until before since', () => {
    const out = auditLogFilterSchema.safeParse({
      organization_id: ORG,
      since: '2027-06-02T00:00:00Z',
      until: '2027-06-01T00:00:00Z',
    });
    expect(out.success).toBe(false);
  });
});
