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
