# Rink Reports Pro reuse inventory

Read-only review of `Max-Facility/Rink-Reports-Pro` at `aeab4c0` (PR #685), Nov 10, 2026. Sources: `brain/*.md`, `AGENTS.md`, `.claude/rules/`, `docs/ops-engine/`, and the source tree. RRP was not modified.

Verdicts: **Copy pattern** = same design, rewritten to Rec Reports tenancy (`organization_id` + `location_id`). **Adapt** = keep the idea and change the shape. **Leave** = rink-specific or out of pilot scope.

## Module by module

| Rec Reports module | RRP source | Verdict | Notes |
| --- | --- | --- | --- |
| Platform: tenancy | `facility_id` everywhere, composite FKs, `facility-fk-guard.test.ts`, `supabase/tests/rls_isolation.sql` | Copy pattern | Same rule, one level up. Port the FK guard test and the SQL isolation harness first. |
| Platform: orgs and multi-site | `organizations` (migration 433), org admins (434), rink switcher, "All my rinks", push to other rinks (436), Compare my rinks (437) | Adapt | RRP added orgs on top of facility tenancy. Rec Reports starts org-first, so a "switcher" becomes a location filter. Push-to-locations is worth copying for checklist templates and rules. |
| Platform: roles | `super_admin`, `admin`, `manager`, `staff` + custom roles; `user_permissions` (module x level); job titles route work, grant nothing; tier rule | Copy pattern | Replaces the role list first drafted in `SECURITY.md` (see below). |
| Platform: auth helpers | `src/lib/auth` (`requireUser`, `requireAdmin`, `requireModuleAdmin`), `src/proxy.ts`, 2FA for admin tier, 30-min admin idle sign-out | Copy pattern | |
| Platform: audit, retention, legal hold | Audit log (7-year minimum), per-module keep periods, archive-before-purge, legal hold | Copy pattern | Retention is after the pilot, but the audit log isn't. |
| Communications | `communication_*`, `notification_outbox`, `push_subscriptions`; Resend email, Web Push; phone-first delivery (430); targets job titles; swipe to acknowledge; high/critical must be opened | Copy pattern | The most mature module (rebuilt Oct 12). The design for acknowledgment, urgency, and delivery state carries over directly. |
| Tasks and workflows | Operations Engine: `ops_events`, `ops_workflow_rules`, `ops_tasks`, `ops_task_templates`; My Work count; handover; rules created disabled | Adapt | The closest match to ADR-0003. RRP fires from events but has no general outbox; Rec Reports makes the outbox the single path. Read `docs/ops-engine/01-08` before designing. |
| Checklists and inspections | Daily Reports (`daily_report_*`: areas, form templates/fields, instances, submissions, notes, day locks); Dasher Boards pass/fail walk; circle check failure creates a work order | Adapt | Daily Reports' configurable forms are the base. Generalize "area" to a space, add "failed item creates corrective task" (already in RRP for circle checks). |
| Incidents | Incident Reports (non-injury: photos, witnesses, follow-ups, types, severity) | Copy pattern | |
| Accidents | Accident Reports ("just the facts", body diagram, treatment level, guardian details for minors, management-only photos, audit of photo views and PDF downloads, no drafts, no auto-context) | Copy pattern | Keep the same restrictions. They match `incident_sensitive_details` in `DATA_MODEL.md`. Known bug to avoid: `markAccidentFollowupDone` requires admin. |
| Facility schedule | Rink Scheduling: bookings, recurrence, drag/resize, find a slot, conflict exclusion, room bookings, coverage sweep (48h "booked without cover"), ICS feeds, display boards | Adapt | Drop resurfaces, billing, and season contracts. Generalize `rink_*` + `facility_rooms` into one `spaces` model. The coverage sweep is exactly the pilot's coverage check. |
| Staff schedule | Employee Scheduling: shifts, open shifts, templates, swaps, drops, time off, availability, publish lock (RLS + trigger), build-from-schedule staffing areas (428) | Copy pattern | Score 93, the strongest module. Rink-free already, apart from "build from ice schedule", which becomes "build from bookings". |
| Offline | Hand-rolled `public/sw.js` + IndexedDB queue, `/api/offline-sync`, idempotent on `client_submission_id`, 12-hour drafts | Copy pattern | Matches ARCHITECTURE.md. Limit it to checklists and incident drafts. |
| Cron and jobs | `/api/cron/*` with `withCronRoute` + `CRON_SECRET`, 19 crons, `drain-notifications` every 5 min | Copy pattern | Use 5 min like RRP, not 1 min. |
| Leave | Refrigeration, Air Quality, Ice Ops, Ice Depth, Dasher Boards (as a module), Billing/invoices, Facility Paperwork, Maintenance work orders, Insights compare | Leave for pilot | Paperwork and work orders come back after the pilot. |

## Working rules from RRP's `brain/never-do.md` that Rec Reports should adopt

- Kelly works in the browser. Give click-by-click steps, not terminal commands.
- No paid service by default. State any cost and name the free option.
- Sessions never write to the production database. Kelly runs release SQL files that end with the migration-ledger insert. PRs that need SQL stay draft until it has run and been verified.
- Never Redeploy or Promote in Vercel. Merge to `main` is the release.
- Readings are "entered by" staff, never "detected".
- Never format a time without the location's time zone.
- Never read a growth table without paging (PostgREST stops at 1000 rows).
- SECURITY DEFINER: in-body tenant/role check, `set search_path = public, pg_temp`, and explicitly revoke anon/authenticated grants.

## Changes this inventory makes to the Rec Reports docs

1. **Roles:** `SECURITY.md` drafted `org_admin` / `facility_manager` / `supervisor`. RRP retired exactly those keys. Use RRP's model instead: `super_admin`, `admin`, `manager`, `staff` + custom roles, permissions as module x level, and job titles for routing.
2. **Cron cadence:** the outbox drain runs every 5 minutes, matching RRP. That still needs Vercel Pro, which RRP already pays for.

