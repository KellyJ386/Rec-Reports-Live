import { describe, expect, it } from 'vitest';
import {
  addRecipient,
  buildAudience,
  buildAudienceOptions,
  channelSettings,
  describeAudience,
  excerpt,
  needsAcknowledgment,
  orderNoticesForReader,
  pageOf,
  parseRecipientIds,
  removeRecipient,
  safeLinkPath,
  urgencyFlag,
  urgencyLabel,
} from './logic';

const L1 = '11111111-1111-4111-8111-111111111111';
const L2 = '22222222-2222-4222-8222-222222222222';
const T1 = '33333333-3333-4333-8333-333333333333';
const T2 = '44444444-4444-4444-8444-444444444444';

describe('safeLinkPath', () => {
  it('accepts app-relative paths', () => {
    expect(safeLinkPath('/app/my-work/abc')).toBe('/app/my-work/abc');
    expect(safeLinkPath('/app/notices?page=2&x=y')).toBe('/app/notices?page=2&x=y');
    expect(safeLinkPath('/')).toBe('/');
  });
  it('refuses anything that could leave the site', () => {
    for (const bad of [
      '//evil.example',
      '///evil.example',
      'https://evil.example',
      'http://evil.example/app',
      'javascript:alert(1)',
      '/\\evil.example',
      '/app//evil.example',
      '/../etc/passwd',
      '/app/../admin',
      '/./x',
      'app/no-leading-slash',
      '',
      ' /app',
      '/app with space',
      '/app\n/x',
      '/app#frag',
      `/${'a'.repeat(500)}`,
    ]) {
      expect(safeLinkPath(bad), bad).toBeNull();
    }
    expect(safeLinkPath(null)).toBeNull();
    expect(safeLinkPath(undefined)).toBeNull();
  });
});

describe('buildAudienceOptions', () => {
  it('offers the organization only to organization-scope admins, and sorts locations', () => {
    const locs = [
      { id: L2, name: 'Zeta Rink' },
      { id: L1, name: 'Alpha Pool' },
    ];
    expect(buildAudienceOptions(true, locs)).toEqual({
      allowOrganization: true,
      allowMultipleLocations: true,
      locations: [locs[1], locs[0]],
    });
    expect(buildAudienceOptions(false, locs)).toMatchObject({
      allowOrganization: false,
      allowMultipleLocations: false,
    });
  });
});

describe('buildAudience', () => {
  const org = { canOrgWide: true, allowedLocationIds: [L1, L2] };
  const loc = { canOrgWide: false, allowedLocationIds: [L1] };

  it('the whole organization, everyone', () => {
    expect(
      buildAudience({ ...org, scope: 'organization', locationIds: [], jobTitleIds: [] }),
    ).toEqual({ ok: true, home: null, audiences: [{ location_id: null, job_title_id: null }] });
  });

  it('refuses the whole organization to a location admin', () => {
    expect(
      buildAudience({ ...loc, scope: 'organization', locationIds: [], jobTitleIds: [] }).ok,
    ).toBe(false);
  });

  it('places x titles', () => {
    const r = buildAudience({
      ...org,
      scope: 'locations',
      locationIds: [L1, L2],
      jobTitleIds: [T1, T2],
    });
    expect(r.ok && r.home).toBeNull();
    expect(r.ok && r.audiences).toHaveLength(4);
    expect(r.ok && r.audiences).toContainEqual({ location_id: L2, job_title_id: T1 });
  });

  it('a location admin sends from that one location', () => {
    expect(
      buildAudience({ ...loc, scope: 'locations', locationIds: [L1], jobTitleIds: [] }),
    ).toEqual({ ok: true, home: L1, audiences: [{ location_id: L1, job_title_id: null }] });
    expect(
      buildAudience({ ...loc, scope: 'locations', locationIds: [L2], jobTitleIds: [] }).ok,
    ).toBe(false);
    expect(
      buildAudience({
        canOrgWide: false,
        allowedLocationIds: [L1, L2],
        scope: 'locations',
        locationIds: [L1, L2],
        jobTitleIds: [],
      }).ok,
    ).toBe(false);
  });

  it('refuses nothing chosen, unknown scopes and bad ids; removes repeats', () => {
    expect(buildAudience({ ...org, scope: 'locations', locationIds: [], jobTitleIds: [] }).ok).toBe(
      false,
    );
    expect(buildAudience({ ...org, scope: 'everyone', locationIds: [], jobTitleIds: [] }).ok).toBe(
      false,
    );
    expect(
      buildAudience({ ...org, scope: 'locations', locationIds: [L1], jobTitleIds: ['nope'] }).ok,
    ).toBe(false);
    const r = buildAudience({
      ...org,
      scope: 'locations',
      locationIds: [L1, L1],
      jobTitleIds: [T1, T1],
    });
    expect(r.ok && r.audiences).toHaveLength(1);
  });
});

describe('describeAudience', () => {
  it('says it in words', () => {
    const rows = [
      { location_id: null, job_title_id: null },
      { location_id: L1, job_title_id: T1 },
      { location_id: L2, job_title_id: null },
    ];
    expect(
      describeAudience(rows, new Map([[L1, 'Main Rink']]), new Map([[T1, 'Lifeguard']])),
    ).toEqual([
      'Everyone at the whole organization',
      'Lifeguard at Main Rink',
      'Everyone at a location',
    ]);
  });
});

describe('orderNoticesForReader', () => {
  const n = (id: string, urgency: string, req: boolean, at: string) => ({
    id,
    urgency,
    requires_acknowledgment: req,
    publish_at: at,
  });
  it('puts notices that still need an acknowledgment first, then urgency, then newest', () => {
    const notices = [
      n('a', 'normal', false, '2026-11-10T10:00:00Z'),
      n('b', 'critical', false, '2026-11-01T10:00:00Z'),
      n('c', 'normal', true, '2026-11-02T10:00:00Z'),
      n('d', 'high', true, '2026-11-03T10:00:00Z'),
      n('e', 'normal', true, '2026-11-04T10:00:00Z'),
      n('f', 'normal', false, '2026-11-11T10:00:00Z'),
    ];
    const order = orderNoticesForReader(notices, new Set(['e'])).map((x) => x.id);
    // d (high, needs ack), c (normal, needs ack), then the rest: b critical, f newest, a, e (older)
    expect(order).toEqual(['d', 'c', 'b', 'f', 'a', 'e']);
  });
  it('knows what still needs an acknowledgment', () => {
    expect(needsAcknowledgment({ id: 'x', requires_acknowledgment: true }, new Set())).toBe(true);
    expect(needsAcknowledgment({ id: 'x', requires_acknowledgment: true }, new Set(['x']))).toBe(
      false,
    );
    expect(needsAcknowledgment({ id: 'x', requires_acknowledgment: false }, new Set())).toBe(false);
  });
});

describe('pageOf', () => {
  const items = Array.from({ length: 60 }, (_, i) => i);
  it('cuts 25 per page and clamps the page', () => {
    expect(pageOf(items, 1, 25).rows).toHaveLength(25);
    expect(pageOf(items, 3, 25).rows).toEqual(items.slice(50));
    expect(pageOf(items, 99, 25)).toMatchObject({ page: 3, total: 60 });
    expect(pageOf([], 5, 25)).toMatchObject({ page: 1, total: 0, rows: [] });
  });
});

describe('recipient lists', () => {
  it('keeps valid, unique ids, at most 50', () => {
    expect(parseRecipientIds(`${L1},bad, ${L2},${L1}`)).toEqual([L1, L2]);
    expect(parseRecipientIds(undefined)).toEqual([]);
    expect(parseRecipientIds([L1, L2])).toEqual([L1, L2]);
    const many = Array.from(
      { length: 60 },
      (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
    );
    expect(parseRecipientIds(many.join(','))).toHaveLength(50);
  });
  it('adds and removes', () => {
    expect(addRecipient([L1], L2)).toEqual([L1, L2]);
    expect(addRecipient([L1], L1)).toEqual([L1]);
    expect(addRecipient([L1], 'x')).toEqual([L1]);
    expect(removeRecipient([L1, L2], L1)).toEqual([L2]);
  });
});

describe('channelSettings', () => {
  it('defaults to on', () => {
    expect(channelSettings([])).toEqual({ email: true, push: true });
    expect(channelSettings([{ channel: 'push', enabled: false }])).toEqual({
      email: true,
      push: false,
    });
  });
});

describe('labels', () => {
  it('flags urgency in words', () => {
    expect(urgencyLabel('critical')).toBe('CRITICAL');
    expect(urgencyFlag('high')).toBe('Important: ');
    expect(urgencyFlag('normal')).toBe('');
  });
  it('shortens text', () => {
    expect(excerpt('a  b\nc', 80)).toBe('a b c');
    expect(excerpt('x'.repeat(100), 10)).toHaveLength(10);
  });
});
