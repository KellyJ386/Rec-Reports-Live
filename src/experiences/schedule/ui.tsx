// Small shared pieces for the schedule screens. Server components with no state.
import Link from 'next/link';

export function ScheduleNav() {
  return (
    <nav aria-label="Schedule">
      <ul>
        <li>
          <Link href="/app/schedule">My schedule</Link>
        </li>
        <li>
          <Link href="/app/schedule/open">Open shifts</Link>
        </li>
        <li>
          <Link href="/app/schedule/swaps">Swaps and drops</Link>
        </li>
        <li>
          <Link href="/app/schedule/time-off">Time off</Link>
        </li>
        <li>
          <Link href="/app/schedule/availability">Availability</Link>
        </li>
      </ul>
    </nav>
  );
}
