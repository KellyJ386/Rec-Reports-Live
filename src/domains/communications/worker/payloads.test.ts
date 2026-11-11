import { describe, expect, it } from 'vitest';
import { FALLBACK_BODY, absoluteLink, buildEmail, buildPushPayload } from './payloads';
import type { NotificationContent } from './types';

const SITE = 'https://app.example.com';
const base: NotificationContent = {
  title: 'Pool closed Friday',
  body: 'Please read it and tap Acknowledge.',
  linkPath: '/app/notices/abc',
  urgency: 'normal',
};

describe('absoluteLink', () => {
  it('builds the link from SITE_URL', () => {
    expect(absoluteLink(SITE, '/app/tasks/1')).toBe('https://app.example.com/app/tasks/1');
  });
  it('falls back to the app home for anything that is not an app-relative path', () => {
    for (const bad of [
      null,
      '//evil.example/x',
      'https://evil.example',
      'javascript:alert(1)',
      '/a b',
      '',
    ]) {
      expect(absoluteLink(SITE, bad)).toBe('https://app.example.com/app');
    }
  });
});

describe('email payload', () => {
  it('carries the title, the summary and the link', () => {
    const m = buildEmail(base, SITE);
    expect(m.subject).toBe('Pool closed Friday');
    expect(m.text).toContain('Please read it and tap Acknowledge.');
    expect(m.text).toContain('https://app.example.com/app/notices/abc');
    expect(m.html).toContain('href="https://app.example.com/app/notices/abc"');
  });
  it('uses the fixed line when there is no summary, for any urgency', () => {
    for (const urgency of ['normal', 'high', 'critical'] as const) {
      const m = buildEmail({ ...base, body: null, urgency }, SITE);
      expect(m.text).toContain(FALLBACK_BODY);
      expect(m.html).toContain(FALLBACK_BODY);
    }
  });
  it('marks a critical notification in the subject only', () => {
    expect(buildEmail({ ...base, urgency: 'critical' }, SITE).subject).toBe(
      'Urgent: Pool closed Friday',
    );
  });
  it('escapes markup in the title and summary', () => {
    const m = buildEmail({ ...base, title: '<b>x</b> & "y"', body: '<script>1</script>' }, SITE);
    expect(m.html).not.toContain('<script>');
    expect(m.html).not.toContain('<b>x</b>');
    expect(m.html).toContain('&lt;b&gt;x&lt;/b&gt; &amp; &quot;y&quot;');
  });
  it('reads only title, body, link and urgency: extra fields cannot leak', () => {
    const rich = {
      ...base,
      personId: 'PERSON-ID-123',
      injuryDetail: 'broken wrist',
      email: 'someone@example.com',
      sourceEventId: 'EVENT-ID-456',
    } as NotificationContent;
    for (const out of [
      JSON.stringify(buildEmail(rich, SITE)),
      JSON.stringify(buildPushPayload(rich, SITE)),
    ]) {
      for (const secret of [
        'PERSON-ID-123',
        'broken wrist',
        'someone@example.com',
        'EVENT-ID-456',
      ]) {
        expect(out).not.toContain(secret);
      }
    }
  });
  it('keeps long text short', () => {
    const m = buildEmail({ ...base, title: 'T'.repeat(500), body: 'B'.repeat(5000) }, SITE);
    expect(m.subject.length).toBeLessThanOrEqual(100);
    expect(m.text.length).toBeLessThan(900);
  });
});

describe('push payload', () => {
  it('has exactly title, body, url and the urgent flag', () => {
    expect(buildPushPayload(base, SITE)).toEqual({
      title: 'Pool closed Friday',
      body: 'Please read it and tap Acknowledge.',
      url: 'https://app.example.com/app/notices/abc',
      urgent: false,
    });
  });
  it('flags critical and falls back to the fixed line without a summary', () => {
    expect(buildPushPayload({ ...base, body: null, urgency: 'critical' }, SITE)).toMatchObject({
      body: FALLBACK_BODY,
      urgent: true,
    });
  });
  it('shortens long text', () => {
    const p = buildPushPayload({ ...base, title: 'T'.repeat(300), body: 'B'.repeat(900) }, SITE);
    expect(p.title.length).toBeLessThanOrEqual(80);
    expect(p.body.length).toBeLessThanOrEqual(140);
  });
});
