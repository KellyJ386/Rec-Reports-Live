# Product spec: pilot

Source: *Rec Reports Enterprise: Master Product & Technical Specification v1.0* (Oct 8, 2026). The pilot scope below was decided on Nov 10, 2026. The full scope doc is at https://claude.ai/artifact/Y7kg4K4sfxCLj5hWauXBEr.

## Goal

By **May 1, 2027**, two mock recreation facilities run a scripted 30-day scenario of bookings, shifts, checklists, and incidents. Everything in that scenario must work end to end, with automated proof of tenant isolation.

## Users

| Role | Screen | Does |
| --- | --- | --- |
| Front-line staff | My Shift | Sees their shift, does tasks and checklists, files incidents, acknowledges notices |
| Supervisor | Shift Control | Watches coverage and open tasks, reviews incidents, writes handoffs |
| Facility admin | Admin | Configures spaces, checklists, forms, schedules, and staff |
| Director | Command Center (read-only) | Views activity across locations |

## In scope

| Module | Must do |
| --- | --- |
| Platform | Organizations, locations, spaces, people, roles, RLS, audit log |
| Communications | Staff inbox, notices, required acknowledgments, shift handoffs, safety alerts |
| Tasks and workflows | Event-driven task creation, assignment by role, due dates, escalation |
| Checklists and inspections | Templates per space, opening and closing checklists, recurring inspections, a corrective task when an item fails |
| Incidents and accidents | Configurable forms, supervisor review, restricted injury details, append-only history, PDF export |
| Facility schedule | Spaces, bookings, recurrence, buffers, conflict blocking, closures |
| Staff schedule | Shifts, positions, qualifications, availability, swaps, coverage checks |

Offline: checklists and incident drafts only.

## Deferred (don't build)

Customer portal and households, program registration, memberships and check-in, payments, POS, invoices, ledger, fitness, aquatics, sports, camps, public APIs and embeds, and RinkReports integration.

## The first demo workflow

Booking confirmed → tasks generated from templates → assigned by role to staff on shift → staff notified (with acknowledgment) → checklist done on My Shift → if an item fails, a corrective task is created and the supervisor alerted → work recorded → shown on Shift Control (readiness and overdue).

## Pilot acceptance

- A manager configures spaces, checklists, forms, and staff without developer help.
- One booking creates its setup, checklist, and cleanup tasks exactly once.
- My Shift works on a phone.
- A failed checklist item creates a corrective task and a supervisor alert.
- An incident goes from filing to supervisor review to PDF export, and injury details are visible only to permitted roles.
- A coverage gap against a booking is flagged before the shift starts.
- Zero cross-organization access in automated tests.
- A retried job creates no duplicates.
- A database restore has been demonstrated.
