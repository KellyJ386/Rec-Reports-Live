/**
 * A short, safe label for an error: never the message (it can hold ids or personal data), only
 * a class. Postgres/PostgREST errors carry a five-character `code` (for example 42501); other
 * errors are named by their constructor name.
 */
export function errorClass(error: unknown): string {
  if (typeof error === 'object' && error !== null) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === 'string' && /^[A-Za-z0-9_]{1,12}$/.test(code)) return `code_${code}`;
    const status = (error as { statusCode?: unknown }).statusCode;
    if (typeof status === 'number') return `http_${status}`;
    const name = (error as { name?: unknown }).name;
    if (typeof name === 'string' && /^[A-Za-z0-9_]{1,40}$/.test(name)) return name;
  }
  return 'unknown';
}

/** Error thrown by a port when the database returns an error (message deliberately dropped). */
export class PortError extends Error {
  readonly code: string | null;
  constructor(operation: string, code: string | null | undefined) {
    super(`${operation} failed`);
    this.name = 'PortError';
    this.code = code && /^[A-Za-z0-9_]{1,12}$/.test(code) ? code : null;
  }
}

/** Log record: ids, counts and error classes only. */
export type LogRecord = Record<string, string | number | boolean | null>;
export type Logger = (record: LogRecord) => void;

export const consoleLogger: Logger = (record) => {
  console.log(JSON.stringify(record));
};
