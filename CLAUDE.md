# Rec Reports: instructions for Claude and other AI developers

Rec Reports is an operations platform for recreation facilities, built by Max Facility Operations. It is a new codebase. It is related to RinkReports Pro, but it is separate from it.

Read these before changing anything:

| File | What it holds |
| --- | --- |
| `docs/PRODUCT_SPEC.md` | Pilot scope: what is in, what is deferred |
| `docs/ARCHITECTURE.md` | Modular monolith, domains, events, jobs |
| `docs/DATA_MODEL.md` | Tenancy, core tables, naming rules |
| `docs/SECURITY.md` | Roles, RLS, data classes, required tests |
| `docs/ROADMAP.md` | Milestones and their gates |
| `docs/REUSE_INVENTORY.md` | What to copy from RinkReports Pro, and its working rules |
| `docs/adr/` | Architecture decisions. Don't contradict one without writing a new ADR. |

## Pilot scope (target start May 1, 2027)

The pilot covers the operations core only: communications, tasks and workflows, checklists and inspections, incidents and accidents, the facility schedule, and the staff schedule. It runs on two **mock** facilities, with no real customer site.

Registration, memberships, payments, POS, the customer portal, fitness, aquatics, sports, and camps are **deferred**. Don't build them. Leave room for them only where `docs/DATA_MODEL.md` says to.

## Stack

Next.js (App Router) + TypeScript, React, Tailwind, Supabase (Postgres, Auth, Storage), Vercel. Background work goes through a transactional outbox plus a durable job runner (ADR-0003).

Rec Reports has its own Supabase project and its own Vercel project. **Never point this repo at RinkReports Pro's Supabase or Vercel projects.**

## Rules

1. **Tenancy first.** Every business table has `organization_id`. Location-scoped tables also have `location_id`. RLS is on for every table and denies by default.
2. **Domains own their tables.** Code in `src/domains/<x>` must not query another domain's tables directly. Call that domain's exported service functions instead.
3. **Events, not side effects.** A significant business action writes a domain event to `outbox_events` in the same transaction. Notifications and generated tasks come from those events, never from inline calls.
4. **Idempotent jobs.** Every job handler is safe to run twice. Use the event ID as the idempotency key.
5. **Migrations only.** Every schema change is a SQL migration in `supabase/migrations/`. No manual changes to production.
6. **Tests with the change.** A new table ships with RLS allow and deny tests. A new workflow ships with a test proving that one event creates exactly one task.
7. **Server-side validation.** Validate every mutation on the server with zod. Never trust client-side checks.
8. **Sensitive data.** Injury and medical details on incidents are restricted (see `docs/SECURITY.md`). Never log them.
9. **Plain language in the UI.** Front-line staff use this on a phone mid-shift, so keep labels short and concrete.

## Reusing RinkReports Pro

RinkReports Pro (`KellyJ386/Rink-Reports-Pro`) is a reference. It is not a dependency. Copy patterns, not code wholesale: re-check tenancy, naming, and the rules above for anything you bring over. Never modify RinkReports Pro from work in this repo.

## Commands

| Command | What it does |
| --- | --- |
| `npm run lint` / `npm run typecheck` / `npm test` / `npm run build` | App checks. CI runs all four. |
| `supabase test db` | Runs the pgTAP suite in `supabase/tests/database/` on the local Supabase stack. CI runs this. |
| `bash scripts/db/test-local.sh` | Same migrations and pgTAP suite on a plain local Postgres with a small Supabase stand-in, for sandboxes where Docker images can't be pulled. Add `--seed` to load `supabase/seed.sql`. |
| `node scripts/seed-users.mjs` | Creates logins for the seeded mock people. Needs the service-role key; never run it against production. |

After every migration: regenerate `src/lib/supabase/database.types.ts`, add pgTAP allow and deny tests, and update `docs/DATA_MODEL.md` and `docs/SECURITY.md`.

## Status and open items

Built (Phases 1 and 2): scaffold and CI, tenancy and access schema with RLS, audit log, sign-in and password reset, two-step sign-in (TOTP) for the admin tier, 30-minute admin idle sign-out, rate limits on sign-in and password reset, invites, plain admin screens, mock seed, the outbox and job runner, tasks and workflow rules, notices, messages, and notifications by email and web push. See `docs/SECURITY.md` for the access model and the Phase 2 review fixes.

Built (Phase 3): staff scheduling. Positions, qualifications, weekly schedules with draft and publish, shifts, shift templates, availability, time off, swaps, drops and open shift claims, with staff and admin screens and an uncovered-shift sweep. See `docs/SECURITY.md` ("Staff scheduling" and "Review fixes (20261113000200)").

GitHub CI runs the app checks and the pgTAP suite on a Supabase stack. Nothing has run on the hosted Supabase project yet, and the Vercel project is not configured, so real sign-in, MFA, invites, email, push and cron are untested ground.

Open items:

- Retention for the audit log (required by `docs/SECURITY.md` before any real data).
- Revoke `service_role` direct reads on tables now that the worker uses the `worker_*` functions.
- Hosted Supabase Auth settings must be set by hand to match `supabase/config.toml`: sign-ups off, 12-character passwords, the exact redirect URL, Auth rate limits, 15-minute JWT, email templates.
- Writes can be refused with SQLSTATE `PT429` (per-person write limits). Map it through `src/lib/db-errors.ts`.
- Private messages and their metadata are hidden from every admin, platform admins included. Keep message content out of the outbox, notifications and the audit log.
- Never create a custom range type: hosted Supabase leaves its constructor functions callable by `anon`. Use `tsrange`, `tstzrange` or `daterange`.
- `authenticated` cannot select the override columns on `shifts`, so never `select *` there. Read overrides through `shift_overrides()`.
- A schedule admin cannot override assignment rules for themself. A schedule holds at most 2,000 shifts. Publishing emits one `schedule.published` event; `shift.opened` is capped at 20 per location per hour.
- Staff scheduling known gaps: losing a qualification or membership does not unassign future shifts; availability is informational only; pick lists cap at 200 people.
