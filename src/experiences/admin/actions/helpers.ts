// Shared helpers for the admin Server Actions. Not a 'use server' file: these are plain
// functions the action files call.
import { redirect } from 'next/navigation';
import { z } from 'zod';
import { getActiveOrganization } from '@/lib/auth';
import { firstIssue, type FormState } from '@/lib/auth/schemas';
import type { Result } from '@/lib/db-errors';

export type AdminFormState = FormState & { values?: Record<string, string> };

export const NOT_CONFIRMED = 'Tick the box to confirm.';

/** The organization the user is working in, from the session, never from the form. */
export async function activeOrgId(): Promise<string> {
  const active = await getActiveOrganization();
  if (!active) redirect('/app');
  return active.organizationId;
}

/** A form value as text; '' when missing or not text. */
export function str(formData: FormData, name: string): string {
  const v = formData.get(name);
  return typeof v === 'string' ? v : '';
}

/** A form value that must be a UUID, else null. */
export function guid(formData: FormData, name: string): string | null {
  const parsed = z.guid().safeParse(str(formData, name).trim());
  return parsed.success ? parsed.data : null;
}

/** A UUID or null for "none chosen" (blank). Returns undefined when a value is present but invalid. */
export function optionalGuid(formData: FormData, name: string): string | null | undefined {
  const text = str(formData, name).trim();
  if (text === '') return null;
  const parsed = z.guid().safeParse(text);
  return parsed.success ? parsed.data : undefined;
}

export function confirmed(formData: FormData): boolean {
  return formData.get('confirm') === 'yes';
}

function echo(formData: FormData): Record<string, string> {
  const values: Record<string, string> = {};
  for (const [key, value] of formData.entries()) {
    if (typeof value === 'string' && !key.startsWith('$ACTION') && key !== 'confirm') {
      values[key] = value;
    }
  }
  return values;
}

/** A refusal. Sends the typed values back so the form can restore them. */
export function bad(formData: FormData, message: string): AdminFormState {
  return { ok: false, message, values: echo(formData) };
}

export function good(message: string): AdminFormState {
  return { ok: true, message };
}

export function zodProblem(formData: FormData, error: z.ZodError): AdminFormState {
  return bad(formData, firstIssue(error));
}

export function fromResult(
  formData: FormData,
  result: Result<unknown>,
  successMessage: string,
): AdminFormState {
  return result.ok ? good(successMessage) : bad(formData, result.message);
}

export const BAD_ID = 'That item could not be found. Reload the page and try again.';
