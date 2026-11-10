import { z } from 'zod';

export const serverEnvSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.url(),
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: z.string().min(1),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  CRON_SECRET: z.string().min(1).optional(),
});

export const publicEnvSchema = serverEnvSchema.pick({
  NEXT_PUBLIC_SUPABASE_URL: true,
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: true,
});

export type ServerEnv = z.infer<typeof serverEnvSchema>;
export type PublicEnv = z.infer<typeof publicEnvSchema>;

/**
 * Public values. Safe in the browser. NEXT_PUBLIC_* must be read as literal
 * property accesses so Next can inline them into the client bundle.
 */
export function getPublicEnv(): PublicEnv {
  return publicEnvSchema.parse({
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
  });
}

/** All values, including secrets. Server only: never import this in a client component. */
export function getServerEnv(): ServerEnv {
  return serverEnvSchema.parse(process.env);
}
