// Runs once when a Next.js server instance starts (see node_modules/next/dist/docs/01-app/
// 02-guides/instrumentation.md). In production it refuses to start when a setting every request
// depends on is missing, instead of failing on each request. It checks names only and never
// prints a value. Skipped while `next build` collects pages (the build may run without runtime
// secrets), in development and in tests.
import { missingProductionEnv } from '@/lib/env';

export function register(): void {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;
  if (process.env.NODE_ENV !== 'production') return;
  if (process.env.NEXT_PHASE === 'phase-production-build') return;
  const missing = missingProductionEnv(process.env);
  if (missing.length > 0) {
    throw new Error(`Server is misconfigured. Missing or invalid settings: ${missing.join(', ')}`);
  }
}
