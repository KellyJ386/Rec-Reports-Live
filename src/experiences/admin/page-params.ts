import { notFound } from 'next/navigation';
import { z } from 'zod';

/** A dynamic route segment that must be a UUID; anything else is a 404. */
export function guidParam(value: string): string {
  const parsed = z.guid().safeParse(value);
  if (!parsed.success) notFound();
  return parsed.data;
}
