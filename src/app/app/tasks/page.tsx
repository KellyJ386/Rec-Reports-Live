import { redirect } from 'next/navigation';

// Notification links point at /app/tasks/<id>; the list itself is "My work".
export default function TasksIndexPage() {
  redirect('/app/my-work');
}
