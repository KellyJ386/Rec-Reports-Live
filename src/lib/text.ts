// Small pure text helpers for the admin screens.

/** Blank or whitespace-only form values become null. */
export function blankToNull(value: FormDataEntryValue | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

/** A whole number from a form value, or null when blank or not a whole number. */
export function toInt(value: FormDataEntryValue | null | undefined): number | null {
  const text = blankToNull(value);
  if (text === null || !/^-?\d+$/.test(text)) return null;
  return Number(text);
}

/**
 * Search words that are safe to place inside a PostgREST filter value. Keeps letters, digits
 * and a few characters found in names and emails; drops everything that could change the
 * filter's meaning (commas, parentheses, quotes, wildcards, backslashes). At most 5 words.
 */
export function searchWords(raw: string | null | undefined): string[] {
  if (!raw) return [];
  return raw
    .slice(0, 100)
    .replace(/[^\p{L}\p{N}@.+'_-]+/gu, ' ')
    .split(' ')
    .map((w) => w.replace(/[.]+$/, ''))
    .filter((w) => w.length > 0)
    .slice(0, 5)
    .map((w) => w.slice(0, 50));
}

/** A lowercase key such as "front_desk" from a display name; always starts with a letter. */
export function keyFromName(name: string, maxLength = 63): string {
  const base = name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  const withLetter = /^[a-z]/.test(base) ? base : `k_${base}`;
  return withLetter.slice(0, maxLength).replace(/_+$/g, '');
}
