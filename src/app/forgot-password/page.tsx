import Link from 'next/link';
import { ForgotPasswordForm } from './form';

export default function ForgotPasswordPage() {
  return (
    <main>
      <h1>Reset your password</h1>
      <ForgotPasswordForm />
      <p>
        <Link href="/sign-in">Back to sign in</Link>
      </p>
    </main>
  );
}
