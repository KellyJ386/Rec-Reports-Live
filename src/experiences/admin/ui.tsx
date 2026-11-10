import Link from 'next/link';
import { buildHref, pageCount } from '@/lib/paging';

export function ErrorMessage({ message }: { message: string }) {
  return <p role="alert">{message}</p>;
}

export function Pager({
  path,
  page,
  total,
  pageSize,
  params = {},
}: {
  path: string;
  page: number;
  total: number;
  pageSize: number;
  params?: Record<string, string | undefined>;
}) {
  const pages = pageCount(total, pageSize);
  return (
    <nav aria-label="Pages">
      <p>
        {total} in total. Page {Math.min(page, pages)} of {pages}.{' '}
        {page > 1 ? (
          <Link href={buildHref(path, { ...params, page: page - 1 })}>Previous</Link>
        ) : null}
        {page > 1 && page < pages ? ' | ' : null}
        {page < pages ? (
          <Link href={buildHref(path, { ...params, page: page + 1 })}>Next</Link>
        ) : null}
      </p>
    </nav>
  );
}

/** Marks archived rows in a list. */
export function ArchivedMark({ archivedAt }: { archivedAt: string | null }) {
  return archivedAt ? <em> (archived)</em> : null;
}

/** Shown when the person can read a screen but not change it. */
export function ViewOnlyNote() {
  return <p>You can look at this but not change it.</p>;
}
