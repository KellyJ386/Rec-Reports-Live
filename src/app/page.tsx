import Link from 'next/link';

export default function HomePage() {
  return (
    <main>
      <h1>Rec Reports</h1>
      <p>
        An operations platform for recreation facilities: communications, tasks, checklists,
        incidents, and the facility and staff schedules.
      </p>
      <p>
        <Link href="/sign-in">Sign in</Link>
      </p>
    </main>
  );
}
