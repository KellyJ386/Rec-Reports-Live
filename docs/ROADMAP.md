# Roadmap

Revised Nov 10, 2026. Full version with the module list, agent team and task lists: https://claude.ai/artifact/JBBmXYigu3DS1csF5B3dAn

Build order: infrastructure first (database, permissions, working features on plain standard components). Visual design is Phase 7. Feature target: SubItUp-style staff tools plus Connect2-style facility operations in one app. This widens the ops-core pilot in ADR-0004; see ADR-0005.

| Phase | Dates | Builds | Gate |
| --- | --- | --- | --- |
| 0. Product and architecture | Done Nov 10, 2026 | Docs, ADRs, reuse inventory | Docs in the repo |
| 1. Platform foundation | Nov 11 to Dec 18 | Scaffold, CI, auth, organizations, locations, spaces, people, roles, permissions, audit log, two mock facilities | Two organizations isolated in automated tests |
| 2. Events, tasks, communications | Dec 21 to Jan 22 | Outbox and jobs, notifications, communications, tasks and workflows | One event creates exactly one task and one notice, even on retry |
| 3. Staff scheduling | Jan 25 to Feb 26 | Shifts, availability, time off, subs, swaps, open shifts | A week of shifts built, published, swapped and covered |
| 4. Facility operations | Mar 1 to Apr 2 | Form builder, checklists, incidents and accidents, daily log, headcounts | Failed check creates a corrective task; injury details restricted |
| 5. Facility schedule and time clock | Apr 5 to Apr 23 | Bookings, coverage check, time clock, offline for checklists and incident drafts | Double-booking impossible; coverage gaps flagged |
| Hardening | Apr 26 to Apr 30 | Security review, restore drill, scripted 30-day scenario | Pilot starts May 1, 2027 |
| 6. Extended modules | May to Jul 2027 | Timesheets and payroll export, certifications, equipment checkout, maintenance, lost and found, documents, dashboards | Same isolation and permission tests |
| 7. Design pass | After Phase 5 screens are stable | One visual system on every screen | Phone and desktop, light and dark |

## Agent team

| Agent | Model | Does |
| --- | --- | --- |
| Orchestrator | Fable 5.2 | Plans phases, splits tasks, reviews, integrates, keeps docs current |
| Database engineer | Opus 5.5 | Migrations, RLS, database functions, scheduling rules |
| Security reviewer | Opus 5.5 | Read-only review of every migration, policy and server action |
| Feature builder | Sonnet 5.5 | Server actions, domain services, screens |
| Test writer | Sonnet 5.5 | Isolation, unit and end-to-end tests |
| Scout and boilerplate | Haiku 5.5 | Search, types, schemas, seed data, lint and typecheck |
