# Architecture

## Shape

One Next.js app and one Postgres database, organized as a **modular monolith** (ADR-0001). The domains have clear boundaries, so a domain can be split into its own service later if scale ever justifies it.

```
src/
  domains/          business logic; each domain owns its tables
    identity/       accounts, people, role assignments
    organizations/  organizations, locations, settings
    resources/      spaces and equipment, hours, closures
    communications/ messages, notices, acknowledgments, handoffs
    workflows/      rules, tasks, escalations, outbox consumers
    checklists/     templates, runs, items, failures
    incidents/      forms, reports, reviews, history
    scheduling/     bookings, recurrence, conflicts
    staffing/       shifts, positions, qualifications, availability, swaps
    audit/          the audit log
  experiences/      UI composed from domains
    employee/       My Shift
    supervisor/     Shift Control
    admin/          Admin
    executive/      Command Center
  lib/              Supabase clients, auth helpers, zod, utilities
supabase/
  migrations/
  tests/            pgTAP RLS and constraint tests
```

**The boundary rule:** a domain exports service functions from `src/domains/<x>/index.ts`. Other domains and experiences import only from that file.

## Requests

- Reads: React Server Components query Supabase through the user's session, so RLS applies.
- Writes: Server Actions validate with zod, then call a domain service. That service runs the change and writes its outbox event in one transaction, using a Postgres function where atomicity matters.
- The service-role key is used only in job workers and admin provisioning, never in request handlers.

## Events and jobs (ADR-0003)

1. A domain writes the business change plus a row in `outbox_events` (id, organization_id, location_id, type, entity_id, payload, schema_version, correlation_id, created_at) in the same transaction.
2. A worker claims pending events with `FOR UPDATE SKIP LOCKED`, runs the handlers, and marks each event done. Failures retry with backoff. After N attempts the event moves to the dead-letter state and shows up in Admin.
3. Handlers are idempotent: generated rows carry `source_event_id` with a unique constraint.

Pilot event types include `booking.confirmed`, `booking.rescheduled`, `booking.cancelled`, `shift.uncovered`, `checklist.item_failed`, `checklist.completed`, `incident.submitted`, `incident.reviewed`, `task.overdue`, and `notice.published`.

Worker runtime: a Vercel Cron route (`withCronRoute` + `CRON_SECRET`, as in RinkReports Pro) that drains the outbox every 5 minutes for the pilot. If the pilot needs lower latency, a Supabase queue with an edge-function worker replaces it. Either way the handlers stay the same.

## Offline

A PWA service worker plus IndexedDB, limited to checklist runs and incident drafts. Synced writes carry a client-generated UUID so retries can't create duplicates.

## Environments

| Env | Supabase | Vercel |
| --- | --- | --- |
| Local | `supabase start` | `next dev` |
| Preview | Rec Reports staging project | Preview deployments per PR |
| Production | Rec Reports prod project | Production |

These are separate from every RinkReports Pro project.
