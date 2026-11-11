import { ActionForm } from './action-form';
import type { AdminFormState } from './actions/helpers';

type Props = {
  action: (previous: AdminFormState, formData: FormData) => Promise<AdminFormState>;
  /** Text on the opening link and the button, e.g. "Archive". */
  label: string;
  /** What the checkbox says, e.g. "Yes, archive this location". */
  question: string;
  /** Hidden fields the action needs, e.g. { id: "..." }. */
  fields: Record<string, string>;
};

/** A destructive action behind a plain checkbox. Works without JavaScript: the server checks it too. */
export function ConfirmAction({ action, label, question, fields }: Props) {
  return (
    <details>
      <summary>{label}</summary>
      <ActionForm action={action} submitLabel={label}>
        {Object.entries(fields).map(([name, value]) => (
          <input key={name} type="hidden" name={name} value={value} />
        ))}
        <p>
          <label>
            <input type="checkbox" name="confirm" value="yes" required /> {question}
          </label>
        </p>
      </ActionForm>
    </details>
  );
}
