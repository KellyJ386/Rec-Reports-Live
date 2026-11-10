import { requireRecentAuthentication } from '@/lib/auth/session';
import { MIN_PASSWORD_LENGTH } from '@/lib/auth/schemas';
import { ResetPasswordForm } from './form';

export default async function ResetPasswordPage() {
  await requireRecentAuthentication();
  return (
    <main>
      <h1>Set a new password</h1>
      <p>Use at least {MIN_PASSWORD_LENGTH} characters.</p>
      <ResetPasswordForm />
    </main>
  );
}
