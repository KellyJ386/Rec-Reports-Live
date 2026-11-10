# ADR-0004: Pilot scope is the operations core on mock facilities

Status: Accepted (Nov 10, 2026, decided by Kelly)

## Context
The master spec's "essential" pilot included registration, memberships, payments, and POS: roughly a year or more of work before go-live. The operations modules are where Max Facility already has proven patterns from RinkReports Pro.

## Decision
The pilot covers communications, tasks/workflows, checklists/inspections, incidents, the facility schedule, and the staff schedule. It runs on two mock facilities, and the target start is May 1, 2027. Commerce and customer-facing modules are deferred, but the data model leaves room for them (see `docs/DATA_MODEL.md`).

## Consequences
- The pilot proves the architecture: tenancy, events, and scheduling. It does not prove the commercial product.
- With no real site, real-world validation needs a first real facility after the pilot.
