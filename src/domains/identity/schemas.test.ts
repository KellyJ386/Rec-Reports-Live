import { describe, expect, it } from 'vitest';
import {
  accountUpdateSchema,
  jobTitleCreateSchema,
  personCreateSchema,
  personUpdateSchema,
  roleCreateSchema,
  roleDefaultPermissionCreateSchema,
  roleUpdateSchema,
  userPermissionCreateSchema,
  userPermissionUpdateSchema,
} from './schemas';

const ORG = '00000000-0000-4000-8000-000000000001';
const PERSON = '00000000-0000-4000-8000-000000000004';
const ROLE = '00000000-0000-4000-8000-000000000005';
const LOC = '00000000-0000-4000-8000-000000000002';

describe('roleCreateSchema', () => {
  const valid = { organization_id: ORG, key: 'lifeguard_lead', name: 'Lifeguard lead', rank: 30 };

  it('accepts a custom role with rank 1-79', () => {
    expect(roleCreateSchema.safeParse(valid).success).toBe(true);
    expect(roleCreateSchema.safeParse({ ...valid, rank: 1 }).success).toBe(true);
    expect(roleCreateSchema.safeParse({ ...valid, rank: 79 }).success).toBe(true);
  });

  it('rejects rank 0, 80 and above (admin and up are reserved)', () => {
    expect(roleCreateSchema.safeParse({ ...valid, rank: 0 }).success).toBe(false);
    expect(roleCreateSchema.safeParse({ ...valid, rank: 80 }).success).toBe(false);
  });

  it('rejects retired keys', () => {
    for (const key of ['org_admin', 'facility_manager', 'gm', 'supervisor']) {
      expect(roleCreateSchema.safeParse({ ...valid, key }).success, key).toBe(false);
    }
  });

  it('rejects system keys', () => {
    for (const key of ['super_admin', 'admin', 'manager', 'staff']) {
      expect(roleCreateSchema.safeParse({ ...valid, key }).success, key).toBe(false);
    }
  });

  it('rejects keys that are not lowercase snake case', () => {
    expect(roleCreateSchema.safeParse({ ...valid, key: 'Lifeguard' }).success).toBe(false);
    expect(roleCreateSchema.safeParse({ ...valid, key: 'lifeguard-lead' }).success).toBe(false);
  });
});

describe('roleUpdateSchema', () => {
  it('allows rank changes within 1-79 and rejects key changes', () => {
    expect(roleUpdateSchema.safeParse({ rank: 40 }).success).toBe(true);
    expect(roleUpdateSchema.safeParse({ key: 'other' }).success).toBe(false);
  });
});

describe('roleDefaultPermissionCreateSchema', () => {
  it('accepts a known module and level', () => {
    const out = roleDefaultPermissionCreateSchema.safeParse({
      role_id: ROLE,
      module_key: 'tasks',
      level: 'edit',
    });
    expect(out.success).toBe(true);
  });

  it('rejects an unknown module and an unknown level', () => {
    expect(
      roleDefaultPermissionCreateSchema.safeParse({
        role_id: ROLE,
        module_key: 'pool_passes',
        level: 'edit',
      }).success,
    ).toBe(false);
    expect(
      roleDefaultPermissionCreateSchema.safeParse({
        role_id: ROLE,
        module_key: 'tasks',
        level: 'owner',
      }).success,
    ).toBe(false);
  });
});

describe('personCreateSchema', () => {
  const valid = {
    organization_id: ORG,
    first_name: 'Jordan',
    last_name: 'Example',
    email: 'jordan@example.com',
  };

  it('accepts a person without an account', () => {
    expect(personCreateSchema.safeParse(valid).success).toBe(true);
  });

  it('rejects a blank last name and a malformed email', () => {
    expect(personCreateSchema.safeParse({ ...valid, last_name: ' ' }).success).toBe(false);
    expect(personCreateSchema.safeParse({ ...valid, email: 'jordan at example' }).success).toBe(
      false,
    );
  });
});

describe('personUpdateSchema', () => {
  it('rejects organization_id and accepts archiving', () => {
    expect(personUpdateSchema.safeParse({ organization_id: ORG }).success).toBe(false);
    expect(personUpdateSchema.safeParse({ archived_at: '2027-05-01T00:00:00Z' }).success).toBe(
      true,
    );
  });
});

describe('accountUpdateSchema', () => {
  it('allows only disabled_at', () => {
    expect(accountUpdateSchema.safeParse({ disabled_at: '2027-05-01T00:00:00Z' }).success).toBe(
      true,
    );
    expect(accountUpdateSchema.safeParse({ user_id: ROLE }).success).toBe(false);
  });
});

describe('userPermissionCreateSchema and update', () => {
  const valid = {
    organization_id: ORG,
    person_id: PERSON,
    location_id: LOC,
    module_key: 'incidents',
    level: 'view',
  };

  it('accepts an override at one location', () => {
    expect(userPermissionCreateSchema.safeParse(valid).success).toBe(true);
  });

  it('rejects a level outside none/view/edit/admin', () => {
    expect(userPermissionCreateSchema.safeParse({ ...valid, level: 'owner' }).success).toBe(false);
  });

  it('updates only level', () => {
    expect(userPermissionUpdateSchema.safeParse({ level: 'edit' }).success).toBe(true);
    expect(userPermissionUpdateSchema.safeParse({ module_key: 'tasks' }).success).toBe(false);
  });
});

describe('jobTitleCreateSchema', () => {
  it('accepts a job title and rejects an empty one', () => {
    expect(
      jobTitleCreateSchema.safeParse({ organization_id: ORG, name: 'Lifeguard' }).success,
    ).toBe(true);
    expect(jobTitleCreateSchema.safeParse({ organization_id: ORG, name: '' }).success).toBe(false);
  });
});
