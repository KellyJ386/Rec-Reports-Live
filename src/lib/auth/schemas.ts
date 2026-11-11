import { z } from 'zod';

const email = z
  .string()
  .trim()
  .min(1, 'Enter your email.')
  .max(320, 'Email is too long.')
  .pipe(z.email('Enter a valid email address.'))
  .transform((v) => v.toLowerCase());

export const MIN_PASSWORD_LENGTH = 12;
// bcrypt (used by Supabase Auth) ignores input beyond 72 bytes.
export const MAX_PASSWORD_LENGTH = 72;

export const signInSchema = z.object({
  email,
  // No strength rules at sign-in: only presence and a sane upper bound.
  password: z.string().min(1, 'Enter your password.').max(256, 'Password is too long.'),
  next: z.string().max(2048).optional(),
});

/** The 6-digit code from an authenticator app. Spaces and dashes people type are ignored. */
export const totpCodeSchema = z
  .string()
  .transform((v) => v.replace(/[\s-]/g, ''))
  .pipe(z.string().regex(/^\d{6}$/, 'Enter the 6-digit code from your app.'));

export const verifyCodeSchema = z.object({
  code: totpCodeSchema,
  next: z.string().max(2048).optional(),
});

export const factorIdSchema = z.guid('That device could not be found.');

export const confirmEnrollSchema = z.object({ factorId: factorIdSchema, code: totpCodeSchema });
export const removeFactorSchema = z.object({ factorId: factorIdSchema, code: totpCodeSchema });

export const forgotPasswordSchema = z.object({ email });

export const resetPasswordSchema = z
  .object({
    password: z
      .string()
      .min(MIN_PASSWORD_LENGTH, `Use at least ${MIN_PASSWORD_LENGTH} characters.`)
      .refine((v) => new TextEncoder().encode(v).length <= MAX_PASSWORD_LENGTH, {
        message: `Use at most ${MAX_PASSWORD_LENGTH} bytes (about ${MAX_PASSWORD_LENGTH} characters).`,
      }),
    confirmPassword: z.string(),
  })
  .refine((v) => v.password === v.confirmPassword, {
    path: ['confirmPassword'],
    message: 'Passwords do not match.',
  });

export const switchOrganizationSchema = z.object({
  organizationId: z.guid('Choose an organization.'),
});

/** Email-link types this app accepts on /auth/confirm. */
export const confirmTypeSchema = z.enum(['recovery', 'invite', 'email']);

export const modulePermissionLevels = ['view', 'edit', 'admin'] as const;
export type ModulePermissionLevel = (typeof modulePermissionLevels)[number];

export const moduleKeySchema = z.string().regex(/^[a-z][a-z0-9_]{0,62}$/);
export const guidSchema = z.guid();

export type FormState = { message?: string; ok?: boolean };

/** First issue message of a zod error, as a plain string. */
export function firstIssue(error: z.ZodError): string {
  return error.issues[0]?.message ?? 'Check the form and try again.';
}
