import { describe, expect, it } from 'vitest';
import {
  messageSendSchema,
  noticeCreateSchema,
  noticePublishSchema,
  noticeUpdateSchema,
  notificationPreferenceSaveSchema,
  notificationPreferenceUpdateSchema,
  pushSubscriptionSaveSchema,
} from './schemas';

const ORG = '00000000-0000-4000-8000-000000000001';
const LOC_A = '00000000-0000-4000-8000-000000000002';
const LOC_B = '00000000-0000-4000-8000-000000000003';
const TITLE = '00000000-0000-4000-8000-000000000005';
const PERSON = '00000000-0000-4000-8000-000000000004';
const PERSON_2 = '00000000-0000-4000-8000-000000000008';
const NOTICE = '00000000-0000-4000-8000-000000000009';

const ok = (s: { safeParse: (v: unknown) => { success: boolean } }, v: unknown) =>
  s.safeParse(v).success;

const base = {
  organization_id: ORG,
  location_id: null,
  title: 'Pool closed Friday',
  body: 'The pool is closed for repairs.',
  urgency: 'normal',
};

describe('noticeCreateSchema', () => {
  it('accepts an organization-wide draft with no audience yet', () => {
    const r = noticeCreateSchema.safeParse(base);
    expect(r.success).toBe(true);
    if (r.success) {
      expect(r.data.audiences).toEqual([]);
      expect(r.data.requires_acknowledgment).toBe(false);
    }
  });

  it('accepts a critical notice that needs acknowledgment, with audiences', () => {
    expect(
      ok(noticeCreateSchema, {
        ...base,
        urgency: 'critical',
        requires_acknowledgment: true,
        audiences: [
          { location_id: null, job_title_id: null },
          { location_id: LOC_A, job_title_id: TITLE },
        ],
      }),
    ).toBe(true);
  });

  it('rejects unknown urgencies and a body over 5000 characters or blank', () => {
    expect(ok(noticeCreateSchema, { ...base, urgency: 'urgent' })).toBe(false);
    expect(ok(noticeCreateSchema, { ...base, body: 'x'.repeat(5001) })).toBe(false);
    expect(ok(noticeCreateSchema, { ...base, body: '   ' })).toBe(false);
  });

  it('rejects a title over 200 characters', () => {
    expect(ok(noticeCreateSchema, { ...base, title: 'x'.repeat(201) })).toBe(false);
  });

  it('rejects expiry at or before the publish time', () => {
    expect(
      ok(noticeCreateSchema, {
        ...base,
        publish_at: '2027-05-01T10:00:00Z',
        expires_at: '2027-05-01T10:00:00Z',
      }),
    ).toBe(false);
    expect(
      ok(noticeCreateSchema, {
        ...base,
        publish_at: '2027-05-01T10:00:00Z',
        expires_at: '2027-05-02T10:00:00Z',
      }),
    ).toBe(true);
  });

  it('rejects a duplicate audience row', () => {
    expect(
      ok(noticeCreateSchema, {
        ...base,
        audiences: [
          { location_id: null, job_title_id: TITLE },
          { location_id: null, job_title_id: TITLE },
        ],
      }),
    ).toBe(false);
  });

  it('rejects an audience at another location for a location notice', () => {
    const located = { ...base, location_id: LOC_A };
    expect(
      ok(noticeCreateSchema, {
        ...located,
        audiences: [{ location_id: LOC_B, job_title_id: null }],
      }),
    ).toBe(false);
    expect(
      ok(noticeCreateSchema, {
        ...located,
        audiences: [{ location_id: null, job_title_id: null }],
      }),
    ).toBe(false);
    expect(
      ok(noticeCreateSchema, {
        ...located,
        audiences: [{ location_id: LOC_A, job_title_id: null }],
      }),
    ).toBe(true);
  });

  it('rejects status, author and publish fields: those are set by the database', () => {
    expect(ok(noticeCreateSchema, { ...base, status: 'published' })).toBe(false);
    expect(ok(noticeCreateSchema, { ...base, author_person_id: PERSON })).toBe(false);
    expect(ok(noticeCreateSchema, { ...base, published_at: '2027-05-01T10:00:00Z' })).toBe(false);
  });
});

describe('noticeUpdateSchema', () => {
  it('accepts a partial edit and refuses an empty one', () => {
    expect(ok(noticeUpdateSchema, { title: 'Pool open again' })).toBe(true);
    expect(ok(noticeUpdateSchema, {})).toBe(false);
  });

  it('does not accept location or organization changes', () => {
    expect(ok(noticeUpdateSchema, { location_id: LOC_A })).toBe(false);
  });

  it('checks expiry against publish time when both are sent', () => {
    expect(
      ok(noticeUpdateSchema, {
        publish_at: '2027-05-01T10:00:00Z',
        expires_at: '2027-04-30T10:00:00Z',
      }),
    ).toBe(false);
  });
});

describe('noticePublishSchema', () => {
  it('accepts a notice id with or without a time', () => {
    expect(ok(noticePublishSchema, { notice_id: NOTICE })).toBe(true);
    expect(ok(noticePublishSchema, { notice_id: NOTICE, publish_at: null })).toBe(true);
    expect(ok(noticePublishSchema, { notice_id: 'nope' })).toBe(false);
  });
});

describe('messageSendSchema', () => {
  const valid = {
    organization_id: ORG,
    recipient_person_ids: [PERSON],
    body: 'Can you cover 6pm?',
  };

  it('accepts one to fifty recipients and trims the body', () => {
    expect(ok(messageSendSchema, valid)).toBe(true);
    expect(ok(messageSendSchema, { ...valid, recipient_person_ids: [] })).toBe(false);
    const many = Array.from(
      { length: 51 },
      (_, i) => `00000000-0000-4000-8000-${String(i + 100).padStart(12, '0')}`,
    );
    expect(ok(messageSendSchema, { ...valid, recipient_person_ids: many })).toBe(false);
    expect(ok(messageSendSchema, { ...valid, recipient_person_ids: [PERSON, PERSON] })).toBe(true);
  });

  it('counts recipients after removing duplicates, as the RPC does', () => {
    const r = messageSendSchema.safeParse({
      ...valid,
      recipient_person_ids: [PERSON, PERSON, PERSON_2],
    });
    expect(r.success).toBe(true);
  });

  it('limits the body to 1-4000 characters', () => {
    expect(ok(messageSendSchema, { ...valid, body: '  ' })).toBe(false);
    expect(ok(messageSendSchema, { ...valid, body: 'x'.repeat(4000) })).toBe(true);
    expect(ok(messageSendSchema, { ...valid, body: 'x'.repeat(4001) })).toBe(false);
  });

  it('rejects a sender field: the sender is always the caller', () => {
    expect(ok(messageSendSchema, { ...valid, sender_person_id: PERSON })).toBe(false);
  });
});

describe('pushSubscriptionSaveSchema', () => {
  const valid = {
    organization_id: ORG,
    endpoint: 'https://push.example.com/send/abc123',
    p256dh:
      'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM',
    auth_secret: 'tBHItJI5svbpez7KI4CCXg',
    user_agent: 'Mobile Safari',
  };

  it('accepts a subscription from an https endpoint', () => {
    expect(ok(pushSubscriptionSaveSchema, valid)).toBe(true);
    expect(ok(pushSubscriptionSaveSchema, { ...valid, user_agent: undefined })).toBe(true);
  });

  it('rejects a non-https or spaced endpoint', () => {
    expect(
      ok(pushSubscriptionSaveSchema, { ...valid, endpoint: 'http://push.example.com/x' }),
    ).toBe(false);
    expect(
      ok(pushSubscriptionSaveSchema, { ...valid, endpoint: 'https://push.example.com/a b' }),
    ).toBe(false);
    expect(
      ok(pushSubscriptionSaveSchema, {
        ...valid,
        endpoint: `https://e.example.com/${'a'.repeat(2000)}`,
      }),
    ).toBe(false);
  });

  it('rejects keys that do not match the stored format', () => {
    expect(ok(pushSubscriptionSaveSchema, { ...valid, p256dh: 'short' })).toBe(false);
    expect(ok(pushSubscriptionSaveSchema, { ...valid, auth_secret: 'bad secret!' })).toBe(false);
  });

  it('rejects a user agent over 300 characters', () => {
    expect(ok(pushSubscriptionSaveSchema, { ...valid, user_agent: 'x'.repeat(301) })).toBe(false);
  });
});

describe('notification preference schemas', () => {
  const valid = { organization_id: ORG, person_id: PERSON, channel: 'email', enabled: false };

  it('accepts email and push, and rejects in-app (always on)', () => {
    expect(ok(notificationPreferenceSaveSchema, valid)).toBe(true);
    expect(ok(notificationPreferenceSaveSchema, { ...valid, channel: 'push' })).toBe(true);
    expect(ok(notificationPreferenceSaveSchema, { ...valid, channel: 'in_app' })).toBe(false);
  });

  it('requires a boolean for enabled', () => {
    expect(ok(notificationPreferenceSaveSchema, { ...valid, enabled: 'no' })).toBe(false);
  });

  it('update changes only enabled', () => {
    expect(ok(notificationPreferenceUpdateSchema, { enabled: true })).toBe(true);
    expect(ok(notificationPreferenceUpdateSchema, { enabled: true, channel: 'push' })).toBe(false);
  });
});
