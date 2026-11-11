import { clip } from '@/lib/cron/run-all';
import type { NotificationContent } from './types';

/** Used when a notification has no summary, and for nothing else: no content beyond this. */
export const FALLBACK_BODY = 'Open Rec Reports to read it';
export const DEFAULT_LINK_PATH = '/app';

/**
 * An absolute link built from SITE_URL (configuration, never a request header). The path must be
 * app-relative; anything else falls back to the app home. Accepts only what the database accepts
 * for notifications.link_path, so a bad row cannot send people elsewhere.
 */
export function absoluteLink(siteUrl: string, linkPath: string | null): string {
  const safe =
    linkPath !== null && /^\/[A-Za-z0-9/_.~%?=&-]*$/.test(linkPath) && !linkPath.startsWith('//')
      ? linkPath
      : DEFAULT_LINK_PATH;
  return new URL(safe, siteUrl).toString();
}

function summaryOf(content: NotificationContent, max: number): string {
  const text = content.body === null ? '' : clip(content.body, max);
  return text === '' ? FALLBACK_BODY : text;
}

function titleOf(content: NotificationContent, max: number): string {
  const text = clip(content.title, max);
  return text === '' ? 'Rec Reports' : text;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export interface EmailMessage {
  subject: string;
  text: string;
  html: string;
}

/**
 * The email for one notification: title, short summary, link. It reads exactly four fields of the
 * content (title, body, linkPath, urgency) and nothing else, so nothing sensitive can ride along.
 * Critical notifications say so in the subject.
 */
export function buildEmail(content: NotificationContent, siteUrl: string): EmailMessage {
  const title = titleOf(content, 100);
  const summary = summaryOf(content, 300);
  const link = absoluteLink(siteUrl, content.linkPath);
  const subject = content.urgency === 'critical' ? `Urgent: ${title}` : title;
  const text = `${title}\n\n${summary}\n\nOpen in Rec Reports: ${link}\n`;
  const html =
    `<div style="font-family:system-ui,sans-serif;font-size:16px;line-height:1.4">` +
    `<p style="font-size:18px;font-weight:600;margin:0 0 8px">${escapeHtml(title)}</p>` +
    `<p style="margin:0 0 16px">${escapeHtml(summary)}</p>` +
    `<p style="margin:0"><a href="${escapeHtml(link)}">Open in Rec Reports</a></p></div>`;
  return { subject, text, html };
}

export interface PushPayload {
  title: string;
  body: string;
  /** Absolute link; the service worker opens it when the notification is tapped. */
  url: string;
  /** Critical notices stay on screen until dismissed. */
  urgent: boolean;
}

export function buildPushPayload(content: NotificationContent, siteUrl: string): PushPayload {
  return {
    title: titleOf(content, 80),
    body: summaryOf(content, 140),
    url: absoluteLink(siteUrl, content.linkPath),
    urgent: content.urgency === 'critical',
  };
}
