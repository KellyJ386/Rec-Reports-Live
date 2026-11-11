// Plain shared pieces for the staff screens. Server components with no state, except the
// ActionForm they wrap (which only shows the result of a Server Action).
import Link from 'next/link';
import { ActionForm } from '@/experiences/admin/action-form';
import { formatInZone } from '@/lib/time';
import {
  describeAssignee,
  priorityLabel,
  statusLabel,
  type TaskActions,
  type TaskRow,
} from '@/domains/workflows';
import type { StaffAccess } from './access';
import {
  commentTaskAction,
  completeTaskAction,
  reopenTaskAction,
  startTaskAction,
} from './actions/tasks';

export function StaffNav({ access }: { access: StaffAccess }) {
  return (
    <nav aria-label="My screens">
      <ul>
        <li>
          <Link href="/app">Home</Link>
        </li>
        {access.tasks ? (
          <li>
            <Link href="/app/my-work">My work</Link>
          </li>
        ) : null}
        {access.schedule ? (
          <li>
            <Link href="/app/schedule">Schedule</Link>
          </li>
        ) : null}
        {access.comms ? (
          <li>
            <Link href="/app/notices">Notices</Link>
          </li>
        ) : null}
        {access.comms ? (
          <li>
            <Link href="/app/messages">Messages</Link>
          </li>
        ) : null}
        <li>
          <Link href="/app/notifications">Notifications</Link>
        </li>
      </ul>
    </nav>
  );
}

/** Text with blank lines becomes paragraphs and single line breaks stay line breaks. */
export function Paragraphs({ text }: { text: string }) {
  return (
    <>
      {text
        .split(/\n{2,}/)
        .map((block) => block.trim())
        .filter((block) => block !== '')
        .map((block, i) => (
          <p key={i}>
            {block.split('\n').map((line, j) => (
              <span key={j}>
                {j > 0 ? <br /> : null}
                {line}
              </span>
            ))}
          </p>
        ))}
    </>
  );
}

export type TaskContext = {
  locationName: string;
  timezone: string;
  assigneeName: string | null;
  jobTitleName: string | null;
};

export function dueText(task: Pick<TaskRow, 'due_at'>, timezone: string): string {
  return task.due_at ? formatInZone(task.due_at, timezone) : 'No due date';
}

/** One task in a list: what it is, where, when it is due, and the buttons this person may use. */
export function TaskItem({
  task,
  context,
  actions,
}: {
  task: TaskRow;
  context: TaskContext;
  actions: TaskActions;
}) {
  return (
    <li>
      <p>
        <Link href={`/app/tasks/${task.id}`}>{task.title}</Link>
      </p>
      <p>
        {statusLabel(task.status)}. Priority: {priorityLabel(task.priority)}. {context.locationName}
        . Due: {dueText(task, context.timezone)}. For:{' '}
        {describeAssignee(context.assigneeName, context.jobTitleName, task.status)}.
      </p>
      <TaskButtons taskId={task.id} actions={actions} withComment={false} />
      <p>
        <Link href={`/app/tasks/${task.id}`}>Details and comments</Link>
      </p>
    </li>
  );
}

/** The forms for the actions a person may take. Each one asks the database, which has the final say. */
export function TaskButtons({
  taskId,
  actions,
  withComment,
}: {
  taskId: string;
  actions: TaskActions;
  withComment: boolean;
}) {
  return (
    <>
      {actions.start ? (
        <ActionForm action={startTaskAction} submitLabel="Start">
          <input type="hidden" name="task_id" value={taskId} />
        </ActionForm>
      ) : null}
      {actions.complete ? (
        <ActionForm action={completeTaskAction} submitLabel="Done">
          <input type="hidden" name="task_id" value={taskId} />
          <p>
            <label>
              Note (optional) <input name="note" maxLength={2000} />
            </label>
          </p>
        </ActionForm>
      ) : null}
      {actions.reopen ? (
        <ActionForm action={reopenTaskAction} submitLabel="Reopen">
          <input type="hidden" name="task_id" value={taskId} />
          <p>
            <label>
              Why (optional) <input name="reason" maxLength={2000} />
            </label>
          </p>
        </ActionForm>
      ) : null}
      {withComment && actions.comment ? (
        <ActionForm action={commentTaskAction} submitLabel="Add comment">
          <input type="hidden" name="task_id" value={taskId} />
          <p>
            <label>
              Comment <textarea name="body" required maxLength={2000} rows={3} />
            </label>
          </p>
        </ActionForm>
      ) : null}
    </>
  );
}
